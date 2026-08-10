from unittest.mock import patch

import pytest

from fenrir.exploit.acr import (
    CONFIG_MAX_SIZE,
    RegistryError,
    _RegistryClient,
    _exchange_refresh_token,
    _manifest_download_units,
    _pick_submanifest,
    _safe_image_dir,
    harvest_container_registry,
    list_registry_admin_creds,
    list_registries_in_scope,
    registry_host,
    registry_name_from_id,
    resolve_registry_capabilities,
)


class FakeResp:
    def __init__(self, status_code, text="", content=b"", json_data=None, headers=None):
        self.status_code = status_code
        self.text = text
        self.content = content
        self._json = json_data
        self.headers = headers or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


def _granted_caps(*ids):
    return [
        {"capability_id": i, "granted": i in ids}
        for i in ["registry.admin_creds", "registry.read_images"]
    ]


def _manifest_list():
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "digest": "sha256:listsub",
                "platform": {"os": "linux", "architecture": "amd64"},
            }
        ],
    }


def _image_manifest(layers=(("sha256:aaa", 20),), config="sha256:cfg", config_size=10):
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"digest": config, "size": config_size, "mediaType": "application/octet-stream"},
        "layers": [
            {"digest": d, "size": s, "mediaType": "application/octet-stream"}
            for d, s in layers
        ],
    }


def _acr_post_side_effect(refresh_token="rt", access_token="at", registry="acct1.azurecr.io"):
    def fake_post(url, data=None, headers=None, timeout=None, **kwargs):
        if url.endswith("/oauth2/exchange"):
            return FakeResp(200, json_data={"refresh_token": refresh_token})
        if url.endswith("/oauth2/token"):
            return FakeResp(200, json_data={"access_token": access_token})
        if "/listCredentials" in url:
            return FakeResp(
                200,
                json_data={
                    "username": "acct1",
                    "passwords": [{"name": "password", "value": "sekret"}],
                },
            )
        return FakeResp(404)
    return fake_post


def _acr_request_side_effect(registry="acct1.azurecr.io", repos=("app", "web")):
    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        host = url.split("/v2")[0]
        assert host == f"https://{registry}"
        if "_catalog" in url:
            return FakeResp(200, json_data={"repositories": list(repos)})
        if "/tags/list" in url:
            return FakeResp(200, json_data={"tags": ["v1", "latest"]})
        if "/manifests/" in url:
            if "listsub" in url:
                return FakeResp(200, json_data=_image_manifest())
            return FakeResp(200, json_data=_manifest_list())
        if "/blobs/" in url:
            if "sha256:cfg" in url:
                return FakeResp(206, content=b'{"env": {}}')
            return FakeResp(206, content=b"layer-data")
        return FakeResp(404)
    return fake_request


def test_registry_name_from_id():
    assert registry_name_from_id(
        "/subscriptions/s/rg/r/providers/Microsoft.ContainerRegistry/registries/acct1"
    ) == "acct1"


def test_registry_host():
    assert registry_host("acct1") == "acct1.azurecr.io"


def test_list_registries_in_scope_paginates_and_breaks_on_403():
    def fake_get(url, headers=None, timeout=None, **kwargs):
        if "sub-1" in url:
            return FakeResp(200, json_data={
                "value": [{"id": "/s/1/r1", "name": "r1", "location": "eastus"}],
                "nextLink": "https://next.example/2",
            })
        if "next.example" in url:
            return FakeResp(200, json_data={
                "value": [{"id": "/s/1/r2", "name": "r2", "location": "westus"}],
            })
        return FakeResp(403)

    subs = [
        type("Sub", (), {"subscription_id": "sub-1"})(),
        type("Sub", (), {"subscription_id": "sub-2"})(),
    ]
    with patch("fenrir.exploit.acr.requests.get", side_effect=fake_get):
        registries = list_registries_in_scope("tok", subs)

    assert [r["name"] for r in registries] == ["r1", "r2"]


def test_resolve_registry_capabilities_uses_effective_actions():
    with patch("fenrir.exploit.arm_enum.get_effective_actions_at_scope") as mock_eff, \
         patch("fenrir.exploit.acr.resolve_capabilities") as mock_caps:
        mock_eff.return_value = {"actions": ["Microsoft.ContainerRegistry/registries/pull/read"]}
        mock_caps.return_value = [{"capability_id": "registry.read_images", "granted": True}]
        caps = resolve_registry_capabilities("tok", "/s/1/r/acct1")
    mock_eff.assert_called_once_with("tok", "/s/1/r/acct1")
    assert caps[0]["capability_id"] == "registry.read_images"


def test_list_registry_admin_creds():
    with patch("fenrir.exploit.acr.requests.post") as mock_post:
        mock_post.side_effect = _acr_post_side_effect()
        creds = list_registry_admin_creds("arm-tok", "/s/1/r/acct1")
    assert creds["username"] == "acct1"
    assert creds["passwords"][0]["value"] == "sekret"


def test_exchange_refresh_token():
    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()) as mp:
        rt = _exchange_refresh_token("aad-token", "acct1.azurecr.io")
    assert rt == "rt"
    data = mp.call_args.kwargs["data"]
    assert data["grant_type"] == "access_token"
    assert data["access_token"] == "aad-token"


def test_exchange_refresh_token_401_raises():
    with patch("fenrir.exploit.acr.requests.post") as mock_post:
        mock_post.return_value = FakeResp(401)
        with pytest.raises(RegistryError):
            _exchange_refresh_token("t", "acct1.azurecr.io")


def test_client_catalog_paginates():
    client = _RegistryClient("acct1.azurecr.io", refresh_token="rt")

    def fake_post(url, data=None, headers=None, timeout=None, **kwargs):
        return FakeResp(200, json_data={"access_token": "at"})

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if "next" in url:
            return FakeResp(200, json_data={"repositories": ["third"]},
                            headers={"Link": ""})
        return FakeResp(
            200,
            json_data={"repositories": ["first", "second"]},
            headers={'Link': '<https://next.example/v2/_catalog?last=second&n=1000>; rel="next"'},
        )

    with patch("fenrir.exploit.acr.requests.post", side_effect=fake_post), \
         patch("fenrir.exploit.acr.requests.request", side_effect=fake_request):
        repos = client.catalog()
    assert repos == ["first", "second", "third"]


def test_client_basic_auth_skips_token_exchange():
    client = _RegistryClient("acct1.azurecr.io", basic_auth="YWJj")

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        assert headers["Authorization"] == "Basic YWJj"
        return FakeResp(200, json_data={"repositories": ["app"]})

    with patch("fenrir.exploit.acr.requests.request", side_effect=fake_request) as mock_req:
        repos = client.catalog()
    assert repos == ["app"]
    assert all("Authorization" not in c.kwargs.get("headers", {})
               or not c.kwargs["headers"].get("Authorization", "").startswith("Bearer")
               for c in mock_req.call_args_list)


def test_client_manifest_and_resolve_list():
    client = _RegistryClient("acct1.azurecr.io", refresh_token="rt")

    def fake_post(url, data=None, headers=None, timeout=None, **kwargs):
        return FakeResp(200, json_data={"access_token": "at"})

    with patch("fenrir.exploit.acr.requests.post", side_effect=fake_post), \
         patch("fenrir.exploit.acr.requests.request", side_effect=_acr_request_side_effect()):
        manifest = client.manifest("app", "latest")
        assert "manifests" in manifest
        resolved = client.resolve_manifest("app", manifest)
        assert "layers" in resolved


def test_pick_submanifest_amd64_preferred():
    m = _manifest_list()
    picked = _pick_submanifest(m)
    assert picked["digest"] == "sha256:listsub"


def test_manifest_download_units():
    units = _manifest_download_units(_image_manifest())
    kinds = [u["kind"] for u in units]
    assert kinds == ["config", "layer"]


def test_safe_image_dir_sanitizes():
    p = _safe_image_dir("/dump", "acct1", "../evil/repo", "v1")
    assert ".." not in str(p)
    assert p.is_relative_to("/dump")


def test_harvest_no_capabilities_no_calls():
    with patch("fenrir.exploit.acr.requests.post") as mp, \
         patch("fenrir.exploit.acr.requests.request") as mr:
        result = harvest_container_registry(
            "arm-tok", "reg-tok", "/s/1/r/acct1",
            _granted_caps(), dump_dir="dump",
        )
    mp.assert_not_called()
    mr.assert_not_called()
    assert "No registry data-plane privileges" in result.note
    assert result.repos == []


def test_harvest_missing_registry_token_note():
    result = harvest_container_registry(
        "arm-tok", None, "/s/1/r/acct1",
        _granted_caps("registry.read_images"), dump_dir="dump",
    )
    assert "--acr-token" in result.note


def test_harvest_admin_creds_path(tmp_path):
    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()), \
         patch("fenrir.exploit.acr.requests.request", side_effect=_acr_request_side_effect()):
        result = harvest_container_registry(
            "arm-tok", "reg-tok", "/s/1/r/acct1",
            _granted_caps("registry.admin_creds"),
            dump_dir=str(tmp_path), list_admin=True,
        )
    assert result.admin_username == "acct1"
    assert result.repos == ["app", "web"]
    assert result.downloaded == 2  # config + layer, deduped across the 4 images
    assert result.to_dict()["capabilities"] == ["registry.admin_creds"]
    image = result.images[0]
    assert image["tag"] == "v1"
    assert len(image["layers"]) == 2


def test_harvest_dedupes_blobs_across_images(tmp_path):
    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if "_catalog" in url:
            return FakeResp(200, json_data={"repositories": ["app", "web"]})
        if "/tags/list" in url:
            return FakeResp(200, json_data={"tags": ["v1", "latest"]})
        if "/manifests/" in url:
            if "web" in url:
                return FakeResp(200, json_data=_image_manifest(layers=(("sha256:web", 30),)))
            return FakeResp(200, json_data=_image_manifest())
        if "/blobs/" in url:
            if "sha256:cfg" in url:
                return FakeResp(206, content=b'{"env": {}}')
            if "sha256:web" in url:
                return FakeResp(206, content=b"web-layer")
            return FakeResp(206, content=b"layer-data")
        return FakeResp(404)

    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()), \
         patch("fenrir.exploit.acr.requests.request", side_effect=fake_request):
        result = harvest_container_registry(
            "arm-tok", "aad-tok", "/s/1/r/acct1",
            _granted_caps("registry.read_images"),
            dump_dir=str(tmp_path), list_admin=False,
        )
    # app:v1/app:latest + web:v1/web:latest share config 'cfg' and layer 'aaa',
    # but web adds a unique layer 'web' -> 3 unique blobs.
    assert result.downloaded == 3
    assert len(result.blobs) == 3
    deduped = [b for img in result.images for b in img["layers"] if b.get("deduped")]
    assert len(deduped) == 5
    web = [img for img in result.images if img["repository"] == "web"][0]
    assert len(web["layers"]) == 2  # cfg (deduped) + web layer


def test_harvest_aad_path_uses_exchange(tmp_path):
    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()) as mp, \
         patch("fenrir.exploit.acr.requests.request", side_effect=_acr_request_side_effect()):
        result = harvest_container_registry(
            "arm-tok", "aad-tok", "/s/1/r/acct1",
            _granted_caps("registry.read_images"),
            dump_dir=str(tmp_path), list_admin=False,
        )
    assert any(c.args[0].endswith("/oauth2/exchange") for c in mp.call_args_list)
    assert result.downloaded == 2
    assert result.to_dict()["capabilities"] == ["registry.read_images"]


def test_harvest_dry_run_no_writes(tmp_path):
    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()), \
         patch("fenrir.exploit.acr.requests.request", side_effect=_acr_request_side_effect()) as mr:
        result = harvest_container_registry(
            "arm-tok", "aad-tok", "/s/1/r/acct1",
            _granted_caps("registry.read_images"),
            dump_dir=str(tmp_path), list_admin=False, dry_run=True,
        )
    assert result.downloaded == 0
    assert result.bytes_downloaded == 0
    assert len(result.images) == 4  # 2 repos x 2 tags
    assert result.images[0]["layers"][0]["downloaded"] is False
    assert not list(tmp_path.rglob("*"))


def test_harvest_compressed_layers_skip_findings(tmp_path):
    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if "_catalog" in url:
            return FakeResp(200, json_data={"repositories": ["app"]})
        if "/tags/list" in url:
            return FakeResp(200, json_data={"tags": ["v1"]})
        if "/manifests/" in url:
            return FakeResp(200, json_data=_image_manifest())
        if "/blobs/" in url:
            if "sha256:cfg" in url:
                return FakeResp(206, content=b'{"env": {}}')
            return FakeResp(206, content=b"\x1f\x8b" + b"compressed-secrets")
        return FakeResp(404)

    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()), \
         patch("fenrir.exploit.acr.requests.request", side_effect=fake_request) as mr:
        result = harvest_container_registry(
            "arm-tok", "aad-tok", "/s/1/r/acct1",
            _granted_caps("registry.read_images"),
            dump_dir=str(tmp_path), list_admin=False,
        )
    assert result.downloaded == 2
    layer = result.blobs[1]
    assert layer["compressed"] is True
    assert result.findings == []


def test_harvest_catalog_denied_errors():
    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        return FakeResp(401)

    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()), \
         patch("fenrir.exploit.acr.requests.request", side_effect=fake_request):
        result = harvest_container_registry(
            "arm-tok", "aad-tok", "/s/1/r/acct1",
            _granted_caps("registry.read_images"),
            dump_dir="dump", list_admin=False,
        )
    assert result.repos == []
    assert any("catalog" in e for e in result.errors)


def test_harvest_config_range_cap(tmp_path):
    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if "_catalog" in url:
            return FakeResp(200, json_data={"repositories": ["app"]})
        if "/tags/list" in url:
            return FakeResp(200, json_data={"tags": ["v1"]})
        if "/manifests/" in url:
            return FakeResp(200, json_data=_image_manifest(config_size=CONFIG_MAX_SIZE + 100))
        if "/blobs/" in url:
            if "sha256:cfg" in url:
                return FakeResp(206, content=b"c" * CONFIG_MAX_SIZE)
            return FakeResp(206, content=b"l" * 10)
        return FakeResp(404)

    with patch("fenrir.exploit.acr.requests.post", side_effect=_acr_post_side_effect()), \
         patch("fenrir.exploit.acr.requests.request", side_effect=fake_request):
        result = harvest_container_registry(
            "arm-tok", "aad-tok", "/s/1/r/acct1",
            _granted_caps("registry.read_images"),
            dump_dir=str(tmp_path), list_admin=False,
        )
    cfg_entries = [b for b in result.blobs if b["kind"] == "config"]
    assert cfg_entries[0]["truncated"] is True
    assert cfg_entries[0]["downloaded_bytes"] == CONFIG_MAX_SIZE
