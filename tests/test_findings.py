from fenrir.exploit.findings import MAX_PER_FILE, finding_counts, scan_bytes


def test_password_in_content():
    findings = scan_bytes(b"db password: hunter2", source="blob://a/c/p.txt", name="p.txt")
    assert any(f["kind"] == "password" for f in findings)


def test_storage_connection_string():
    data = (
        b"DefaultEndpointsProtocol=https;AccountName=acct1;"
        b"AccountKey=YWJjMTIz;EndpointSuffix=core.windows.net"
    )
    findings = scan_bytes(data, source="s", name="conn.txt")
    assert any(f["kind"] == "storage_connection" for f in findings)


def test_private_key():
    data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    findings = scan_bytes(data, source="s", name="id_rsa")
    assert any(f["kind"] == "private_key" for f in findings)


def test_jwt():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    findings = scan_bytes(token.encode(), source="s", name="t.txt")
    assert any(f["kind"] == "jwt" for f in findings)


def test_aws_key():
    findings = scan_bytes(b"AKIAIOSFODNN7EXAMPLE", source="s", name="a.txt")
    assert any(f["kind"] == "aws_key" for f in findings)


def test_sensitive_filename_only():
    findings = scan_bytes(b"nothing sensitive here", source="s", name=".env")
    assert any(f["kind"] == "config_file" for f in findings)
    assert findings[-1]["snippet"] == ".env"


def test_binary_data_handled():
    findings = scan_bytes(b"\x00\x01\x02\x03\xff\xfe" * 100, source="s", name="blob.bin")
    assert findings == []


def test_result_is_deduped_and_capped():
    data = b"password: abc\npassword: def\npassword: ghi\n" * 200
    findings = scan_bytes(data, source="s", name="x.txt")
    assert len(findings) <= 25


def test_finding_counts():
    counts = finding_counts([
        {"kind": "password"}, {"kind": "password"}, {"kind": "jwt"},
    ])
    assert counts == {"password": 2, "jwt": 1}
    assert finding_counts(None) == {}
