import base64
import hashlib
import hmac
import re
from unittest.mock import patch

import pytest

from fenrir.exploit.storage import (
    StorageAccessError,
    account_name_from_id,
    _canonicalized_resource,
    _data_request,
    _get_bytes,
    _shared_key_auth,
    _string_to_sign,
    download_blob,
    harvest_storage_account,
    list_blobs,
    list_containers,
    list_shares,
    list_storage_account_keys,
    list_storage_accounts_in_scope,
    walk_share_files,
)

ZERO_KEY = base64.b64encode(b"\x00" * 64).decode()


class FakeResp:
    def __init__(self, status_code, text="", content=b"", json_data=None):
        self.status_code = status_code
        self.text = text
        self.content = content
        self._json = json_data

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


def _containers_xml(names, next_marker=None):
    inner = "".join(f"<Container><Name>{n}</Name></Container>" for n in names)
    marker = f"<NextMarker>{next_marker}</NextMarker>" if next_marker else ""
    return f"<EnumerationResults><Containers>{inner}</Containers>{marker}</EnumerationResults>"


def _blobs_xml(blobs):
    inner = "".join(
        f"<Blob><Name>{n}</Name><Properties><Content-Length>{s}</Content-Length></Properties></Blob>"
        for n, s in blobs
    )
    return f"<EnumerationResults><Blobs>{inner}</Blobs></EnumerationResults>"


def _shares_xml(shares):
    inner = "".join(f"<Share><Name>{n}</Name></Share>" for n in shares)
    return f"<EnumerationResults><Shares>{inner}</Shares></EnumerationResults>"


def _files_xml(entries):
    inner = ""
    for name, size, is_dir in entries:
        if is_dir:
            inner += f"<Directory><Name>{name}</Name></Directory>"
        else:
            inner += (
                f"<File><Name>{name}</Name>"
                f"<Properties><Content-Length>{size}</Content-Length></Properties></File>"
            )
    return f"<EnumerationResults><Entries>{inner}</Entries></EnumerationResults>"


def _granted_caps(*ids):
    return [{"capability_id": i, "granted": i in ids} for i in
            ["storage.list_keys", "storage.list_containers", "storage.read_blobs",
             "storage.write_blobs", "storage.delete_blobs", "storage.read_files"]]


def _blob_get_side_effect(blobs_by_container=None, download_status=200):
    blobs_by_container = blobs_by_container or {}

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if method != "GET":
            return FakeResp(405)
        if "comp=list" in url and "restype=container" not in url:
            return FakeResp(200, _containers_xml(list(blobs_by_container)))
        if "comp=list" in url:
            for container, blobs in blobs_by_container.items():
                if f"/{container}?" in url:
                    return FakeResp(200, _blobs_xml(blobs))
            return FakeResp(403)
        if download_status == 403:
            return FakeResp(403)
        return FakeResp(download_status, content=b"secret-data")

    return fake_request


def test_account_name_from_id():
    assert account_name_from_id(
        "/subscriptions/s/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/acct1"
    ) == "acct1"


def test_shared_key_signature_format():
    account = "myaccount"
    url = (
        "https://myaccount.blob.core.windows.net/mycontainer"
        "?restype=container&comp=list"
    )
    headers = {
        "x-ms-date": "Wed, 23 Oct 2019 21:00:00 GMT",
        "x-ms-version": "2019-02-02",
    }
    hdrs = _shared_key_auth(
        ZERO_KEY, "GET", url, dict(headers), account, include_params=True
    )
    assert hdrs["Authorization"] == f"SharedKey {account}:{_expected_sig(headers)}"

    sts = _string_to_sign("GET", url, hdrs, account, True)
    assert sts == _expected_string_to_sign()


def _expected_string_to_sign() -> str:
    return (
        "GET\n"
        + "\n" * 11
        + "x-ms-date:Wed, 23 Oct 2019 21:00:00 GMT\n"
        + "x-ms-version:2019-02-02\n"
        + "/myaccount/mycontainer\n"
        + "comp:list\n"
        + "restype:container"
    )


def _expected_sig(headers) -> str:
    sts = (
        "GET\n"
        + "\n" * 11
        + "x-ms-date:Wed, 23 Oct 2019 21:00:00 GMT\n"
        + "x-ms-version:2019-02-02\n"
        + "/myaccount/mycontainer\n"
        + "comp:list\n"
        + "restype:container"
    )
    return base64.b64encode(
        hmac.new(b"\x00" * 64, sts.encode(), hashlib.sha256).digest()
    ).decode()


def test_shared_key_skips_xms_query_params_in_resource():
    url = (
        "https://myaccount.blob.core.windows.net/?comp=list&restype=container"
        "&x-ms-thing=ignored"
    )
    sts = _string_to_sign("GET", url, {}, "myaccount", True)
    assert "x-ms-thing" not in sts
    assert "comp:list" in sts


def test_list_keys_calls_management_plane():
    with patch("fenrir.exploit.storage.requests.post") as mock_post:
        mock_post.return_value = FakeResp(
            200,
            json_data={"keys": [{"keyName": "key1", "permissions": "F", "value": "abc=="}]},
        )
        keys = list_storage_account_keys("arm-tok", "/sub/1/.../storageAccounts/acct1")
    url = mock_post.call_args.args[0]
    assert url.endswith("/listKeys") or "/listKeys?" in url
    assert "api-version=2023-01-01" in url
    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer arm-tok"
    assert keys[0]["value"] == "abc=="


def test_list_keys_raises_on_error():
    with patch("fenrir.exploit.storage.requests.post") as mock_post:
        mock_post.return_value = FakeResp(403)
        with pytest.raises(StorageAccessError):
            list_storage_account_keys("arm-tok", "/sub/1/.../storageAccounts/acct1")


def test_list_containers_paginates():
    with patch("fenrir.exploit.storage.requests.request") as mock_req:
        mock_req.side_effect = [
            FakeResp(200, _containers_xml(["c1", "c2"], next_marker="m1")),
            FakeResp(200, _containers_xml(["c3"])),
        ]
        containers = list_containers("tok", "acct1")
    assert containers == ["c1", "c2", "c3"]
    assert mock_req.call_count == 2
    assert "Bearer tok" in mock_req.call_args.kwargs["headers"]["Authorization"]


def test_list_containers_shared_key_auth():
    with patch("fenrir.exploit.storage.requests.request") as mock_req:
        mock_req.return_value = FakeResp(200, _containers_xml(["c1"]))
        list_containers(None, "acct1", key=ZERO_KEY)
    headers = mock_req.call_args.kwargs["headers"]
    assert headers["Authorization"].startswith("SharedKey acct1:")


def test_list_blobs():
    with patch("fenrir.exploit.storage.requests.request") as mock_req:
        mock_req.return_value = FakeResp(200, _blobs_xml([("a.txt", 10), ("b.txt", 20)]))
        blobs = list_blobs("tok", "acct1", "cont1")
    assert blobs == [{"name": "a.txt", "size": 10}, {"name": "b.txt", "size": 20}]


def test_walk_share_files_recursive_dedup():
    tree = {
        "": [("dir1", 0, True), ("top.txt", 10, False)],
        "dir1": [("nested.txt", 20, False), ("deeper", 0, True)],
        "dir1/deeper": [("leaf.bin", 30, False)],
    }

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        rest = url.split("?")[0]
        prefix = rest.split(".file.core.windows.net/share1", 1)[-1].strip("/")
        if prefix == "":
            return FakeResp(200, _files_xml(tree[""]))
        return FakeResp(200, _files_xml(tree[prefix]))

    with patch("fenrir.exploit.storage.requests.request", side_effect=fake_request):
        files = walk_share_files("tok", "acct1", "share1")

    paths = {f["path"] for f in files}
    assert paths == {"top.txt", "dir1/nested.txt", "dir1/deeper/leaf.bin"}
    assert len(paths) == len(files)
    by_path = {f["path"]: f["size"] for f in files}
    assert by_path["dir1/nested.txt"] == 20
    assert by_path["dir1/deeper/leaf.bin"] == 30


def test_list_storage_accounts_in_scope_paginates_and_breaks_on_403():
    def fake_get(url, headers=None, timeout=None, **kwargs):
        if "sub-1" in url:
            return FakeResp(200, json_data={
                "value": [{"id": "/s/1/a1", "name": "a1", "location": "eastus"}],
                "nextLink": "https://next.example/2",
            })
        if "next.example" in url:
            return FakeResp(200, json_data={
                "value": [{"id": "/s/1/a2", "name": "a2", "location": "westus"}],
            })
        return FakeResp(403)

    subs = [
        type("Sub", (), {"subscription_id": "sub-1"})(),
        type("Sub", (), {"subscription_id": "sub-2"})(),
    ]
    with patch("fenrir.exploit.storage.requests.get", side_effect=fake_get):
        accounts = list_storage_accounts_in_scope("tok", subs)

    assert [a["name"] for a in accounts] == ["a1", "a2"]


def test_harvest_no_capabilities_no_calls():
    with patch("fenrir.exploit.storage.requests.request") as mock_req, \
         patch("fenrir.exploit.storage.requests.post") as mock_post:
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1",
            _granted_caps(), dump_dir="dump", list_keys=True,
        )
    mock_req.assert_not_called()
    mock_post.assert_not_called()
    assert "No storage privileges" in result.note
    assert result.keys == []


def test_harvest_missing_storage_token_note():
    result = harvest_storage_account(
        "arm-tok", None, "/.../storageAccounts/acct1",
        _granted_caps("storage.read_blobs"), dump_dir="dump",
    )
    assert "storage token" in (result.note or "")


def test_harvest_keys_only_reaches_content_via_shared_key(tmp_path):
    caps = _granted_caps("storage.list_keys")
    with patch("fenrir.exploit.storage.requests.post") as mock_post, \
         patch("fenrir.exploit.storage.requests.request",
               side_effect=_blob_get_side_effect({"cont1": [("secret.txt", 5)]})):
        mock_post.return_value = FakeResp(
            200, json_data={"keys": [{"keyName": "k", "permissions": "F", "value": ZERO_KEY}]}
        )
        result = harvest_storage_account(
            "arm-tok", None, "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path), list_keys=True,
        )
    assert len(result.keys) == 1
    assert result.containers == ["cont1"]
    assert result.downloaded == 1
    assert result.to_dict()["capabilities"] == ["storage.list_keys"]


def test_harvest_full_download_with_range_cap(tmp_path):
    caps = _granted_caps("storage.list_keys", "storage.read_blobs")

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if "comp=list" in url and "restype=container" not in url:
            return FakeResp(200, _containers_xml(["cont1"]))
        if "comp=list" in url:
            return FakeResp(200, _blobs_xml([("big.bin", 1000)]))
        assert headers["Range"] == "bytes=0-9"
        return FakeResp(206, content=b"x" * 10)

    with patch("fenrir.exploit.storage.requests.request", side_effect=fake_request) as mock_req, \
         patch("fenrir.exploit.storage.requests.post") as mock_post:
        mock_post.return_value = FakeResp(200, json_data={"keys": []})
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path), max_size=10, list_keys=True,
        )

    assert result.downloaded == 1
    assert result.bytes_downloaded == 10
    file_entry = result.files[0]
    assert file_entry["truncated"] is True
    assert file_entry["name"] == "big.bin"
    assert (tmp_path / file_entry["path"]).read_bytes() == b"x" * 10
    assert result.to_dict()["capabilities"] == ["storage.list_keys", "storage.read_blobs"]


def test_harvest_403_list_containers_skipped(tmp_path):
    caps = _granted_caps("storage.read_blobs")
    with patch("fenrir.exploit.storage.requests.request") as mock_req:
        mock_req.return_value = FakeResp(403)
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path),
        )
    assert result.containers == []
    assert result.downloaded == 0
    assert any("list containers failed" in e for e in result.errors)


def test_harvest_403_download_continues(tmp_path):
    caps = _granted_caps("storage.read_blobs")
    with patch("fenrir.exploit.storage.requests.request",
               side_effect=_blob_get_side_effect(
                   {"c1": [("secret.txt", 5)], "c2": [("other.txt", 5)]},
                   download_status=403,
               )):
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path),
        )
    assert result.containers == ["c1", "c2"]
    assert result.downloaded == 0
    assert len(result.skipped) == 2
    assert "secret.txt" in result.skipped[0]
    assert result.errors == []


def test_harvest_dry_run_no_writes(tmp_path):
    caps = _granted_caps("storage.read_blobs")
    with patch("fenrir.exploit.storage.requests.request",
               side_effect=_blob_get_side_effect({"cont1": [("a.txt", 5)]})):
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path), dry_run=True,
        )
    assert result.downloaded == 0
    assert result.bytes_downloaded == 0
    assert len(result.files) == 1
    assert result.files[0]["downloaded"] is False
    assert result.files[0]["downloaded_bytes"] == 0
    assert not any((tmp_path).rglob("a.txt"))


def test_harvest_azure_files_via_shared_key(tmp_path):
    caps = _granted_caps("storage.list_keys", "storage.read_files")

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if ".file.core.windows.net" in url:
            if "restype=directory&comp=list" in url:
                return FakeResp(200, _files_xml([("config.json", 12, False)]))
            return FakeResp(200, _shares_xml(["share1"]))
        if "comp=list" in url:
            return FakeResp(200, _containers_xml([]))
        return FakeResp(403)

    with patch("fenrir.exploit.storage.requests.post") as mock_post, \
         patch("fenrir.exploit.storage.requests.request", side_effect=fake_request):
        mock_post.return_value = FakeResp(
            200, json_data={"keys": [{"keyName": "k", "permissions": "F", "value": ZERO_KEY}]}
        )
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path), list_keys=True,
        )

    assert result.shares == ["share1"]
    assert len(result.share_files) == 1
    entry = result.share_files[0]
    assert entry["name"] == "config.json"
    assert (tmp_path / entry["path"]).exists()


def test_harvest_records_findings(tmp_path):
    caps = _granted_caps("storage.read_blobs")

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if "comp=list" in url and "restype=container" not in url:
            return FakeResp(200, _containers_xml(["cont1"]))
        if "comp=list" in url:
            return FakeResp(200, _blobs_xml([("secrets.env", 5)]))
        return FakeResp(200, content=b"PASSWORD=hunter2")

    with patch("fenrir.exploit.storage.requests.request", side_effect=fake_request):
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path),
        )
    assert result.downloaded == 1
    assert any(f["kind"] == "password" for f in result.findings)
    assert "password" in result.files[0]["findings"]


def test_harvest_path_traversal_sanitized(tmp_path):
    caps = _granted_caps("storage.read_blobs")
    with patch("fenrir.exploit.storage.requests.request",
               side_effect=_blob_get_side_effect({"cont1": [("../evil.txt", 3)]})):
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path), dry_run=True,
        )
    assert ".." not in result.files[0]["path"]


def test_canonicalized_resource_root_path_has_trailing_slash():
    assert _canonicalized_resource(
        "myaccount",
        "https://myaccount.blob.core.windows.net/?comp=list&maxresults=1000",
        True,
    ) == "/myaccount/\ncomp:list\nmaxresults:1000"


def test_canonicalized_resource_root_file_service_trailing_slash():
    assert _canonicalized_resource(
        "myaccount",
        "https://myaccount.file.core.windows.net/?comp=list&maxresults=1000",
        True,
    ) == "/myaccount/\ncomp:list\nmaxresults:1000"


def test_canonicalized_resource_query_values_are_decoded():
    resource = _canonicalized_resource(
        "myaccount",
        "https://myaccount.blob.core.windows.net/cont?prefix=a%2Fb&delimiter=%2F",
        True,
    )
    assert "\nprefix:a/b" in resource
    assert "a%2Fb" not in resource


def test_data_request_adds_xms_date_and_version():
    captured = {}

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        captured["headers"] = headers
        return FakeResp(200, content=b"")

    with patch("fenrir.exploit.storage.requests.request", side_effect=fake_request):
        _data_request(
            "GET",
            "https://myaccount.blob.core.windows.net/?comp=list",
            account="myaccount",
            storage_token="tok",
        )

    hdrs = captured["headers"]
    assert hdrs["x-ms-version"] == "2023-11-03"
    assert re.fullmatch(
        r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT",
        hdrs["x-ms-date"],
    )


def test_list_shares_signs_query_params_and_uses_default_include():
    with patch("fenrir.exploit.storage._data_request") as mock:
        mock.return_value = FakeResp(200, _shares_xml(["share1"]))
        list_shares("tok", "myaccount")

    url, kwargs = mock.call_args
    assert kwargs.get("include_params", True) is True
    sts = _string_to_sign(
        "GET",
        "https://myaccount.file.core.windows.net/?comp=list&maxresults=1000",
        {"x-ms-date": "Wed, 23 Oct 2019 21:00:00 GMT", "x-ms-version": "2019-02-02"},
        "myaccount",
        True,
    )
    assert "/myaccount/\ncomp:list\nmaxresults:1000" in sts


def test_get_bytes_retries_without_range_on_416():
    with patch("fenrir.exploit.storage._data_request",
               side_effect=[FakeResp(416), FakeResp(200, content=b"")]) as mock:
        data = _get_bytes(
            "https://myaccount.blob.core.windows.net/cont/empty.txt",
            account="myaccount", storage_token="tok", max_size=1024,
        )
    assert data == b""
    assert mock.call_count == 2
    assert "Range" not in (mock.call_args_list[1].kwargs.get("headers") or {})


def test_harvest_nested_file_url_single_slash(tmp_path):
    caps = _granted_caps("storage.read_files")
    download_urls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if ".file.core.windows.net" not in url:
            return FakeResp(403)
        if "comp=list" in url:
            if "restype=directory" in url:
                if "/dir1" in url:
                    return FakeResp(200, _files_xml([("config.json", 3, False)]))
                return FakeResp(200, _files_xml([("dir1", 0, True)]))
            return FakeResp(200, _shares_xml(["share1"]))
        download_urls.append(url)
        return FakeResp(200, content=b"cfg")

    with patch("fenrir.exploit.storage.requests.request", side_effect=fake_request):
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path),
        )

    assert result.downloaded == 1
    assert download_urls == [
        "https://acct1.file.core.windows.net/share1/dir1/config.json"
    ]
    assert "//" not in download_urls[0].split(".file.core.windows.net", 1)[1]


def test_download_blob_keeps_slash_in_name(tmp_path):
    urls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        urls.append(url)
        return FakeResp(200, content=b"data")

    with patch("fenrir.exploit.storage.requests.request", side_effect=fake_request):
        download_blob("tok", "acct1", "cont1", "dir/file.txt", tmp_path / "out.txt", max_size=10)

    assert urls[0] == "https://acct1.blob.core.windows.net/cont1/dir/file.txt"
    assert "%2F" not in urls[0]


def test_harvest_nested_blob_url_keeps_slash(tmp_path):
    caps = _granted_caps("storage.read_blobs")
    download_urls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if "comp=list" in url and "restype=container" not in url:
            return FakeResp(200, _containers_xml(["cont1"]))
        if "comp=list" in url:
            return FakeResp(200, _blobs_xml([("dir/file.txt", 5)]))
        download_urls.append(url)
        return FakeResp(200, content=b"data")

    with patch("fenrir.exploit.storage.requests.request", side_effect=fake_request):
        result = harvest_storage_account(
            "arm-tok", "storage-tok", "/.../storageAccounts/acct1", caps,
            dump_dir=str(tmp_path),
        )

    assert result.downloaded == 1
    assert download_urls == ["https://acct1.blob.core.windows.net/cont1/dir/file.txt"]
