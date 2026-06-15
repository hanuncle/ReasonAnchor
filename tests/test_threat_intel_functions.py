import hashlib
import json
import socket
import urllib.error
import urllib.parse
import zipfile
from io import BytesIO

from tests.module_function_helpers import reverse_function_module

mb_download_module = reverse_function_module("malwarebazaar_download_sample.py")
mb_module = reverse_function_module("malwarebazaar_hash_lookup.py")
vt_behaviour_module = reverse_function_module("virustotal_behaviour_summary.py")
vt_module = reverse_function_module("virustotal_hash_lookup.py")

MalwareBazaarDownloadSampleFunction = mb_download_module.MalwareBazaarDownloadSampleFunction
MalwareBazaarHashLookupFunction = mb_module.MalwareBazaarHashLookupFunction
VirusTotalBehaviourSummaryFunction = vt_behaviour_module.VirusTotalBehaviourSummaryFunction
VirusTotalHashLookupFunction = vt_module.VirusTotalHashLookupFunction

SHA256 = "a" * 64


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class FakeBytesResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.payload


def hash_context(config=None, sha256=SHA256):
    return {
        "results": {"hash": {"status": "success", "data": {"sha256": sha256}}},
        "config": config or {},
    }


def http_error(status_code):
    return urllib.error.HTTPError("https://example.test", status_code, "error", {}, None)


def test_virustotal_hash_lookup_missing_inputs() -> None:
    fn = VirusTotalHashLookupFunction()

    assert fn.run({"results": {}, "config": {}}, {}).error["code"] == "missing_hash_result"
    assert (
        fn.run(hash_context({"virustotal": {"api_key": "test"}}, ""), {}).error["code"]
        == "missing_sha256"
    )
    assert fn.run(hash_context(), {}).error["code"] == "missing_api_key"


def test_virustotal_hash_lookup_mock_success_and_http_errors(monkeypatch) -> None:
    def fake_urlopen(request, timeout):
        return FakeResponse(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 1},
                        "meaningful_name": "sample.exe",
                        "tags": ["tag1"],
                    }
                }
            }
        )

    monkeypatch.setattr(vt_module.urllib.request, "urlopen", fake_urlopen)
    result = VirusTotalHashLookupFunction().run(
        hash_context({"virustotal": {"api_key": "test-key"}}),
        {},
    )
    assert result.status == "success"
    assert result.data["found"] is True
    assert result.data["detection"] == "malicious:1"

    for status_code, expected in [(404, "not_found"), (401, "unauthorized"), (403, "forbidden"), (429, "rate_limited")]:
        monkeypatch.setattr(
            vt_module.urllib.request,
            "urlopen",
            lambda request, timeout, status_code=status_code: (_ for _ in ()).throw(
                http_error(status_code)
            ),
        )
        result = VirusTotalHashLookupFunction().run(
            hash_context({"virustotal": {"api_key": "test-key"}}),
            {},
        )
        assert result.status == "error"
        assert result.error["code"] == expected


def test_virustotal_hash_lookup_timeout_and_request_failed(monkeypatch) -> None:
    monkeypatch.setattr(
        vt_module.urllib.request,
        "urlopen",
        lambda request, timeout: (_ for _ in ()).throw(socket.timeout()),
    )
    timeout_result = VirusTotalHashLookupFunction().run(
        hash_context({"virustotal": {"api_key": "test-key"}}),
        {},
    )

    monkeypatch.setattr(
        vt_module.urllib.request,
        "urlopen",
        lambda request, timeout: (_ for _ in ()).throw(urllib.error.URLError("boom")),
    )
    failed_result = VirusTotalHashLookupFunction().run(
        hash_context({"virustotal": {"api_key": "test-key"}}),
        {},
    )

    assert timeout_result.error["code"] == "timeout"
    assert failed_result.error["code"] == "request_failed"


def test_malwarebazaar_hash_lookup_mock_success_and_404(monkeypatch) -> None:
    monkeypatch.setattr(
        mb_module.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse(
            {
                "query_status": "ok",
                "data": [{"signature": "TestSig", "tags": ["tag"], "file_type": "exe"}],
            }
        ),
    )
    result = MalwareBazaarHashLookupFunction().run(
        hash_context({"malwarebazaar": {"auth_key": "test-key"}}),
        {},
    )
    assert result.status == "success"
    assert result.data["signature"] == "TestSig"

    monkeypatch.setattr(
        mb_module.urllib.request,
        "urlopen",
        lambda request, timeout: (_ for _ in ()).throw(http_error(404)),
    )
    not_found = MalwareBazaarHashLookupFunction().run(
        hash_context({"malwarebazaar": {"auth_key": "test-key"}}),
        {},
    )
    assert not_found.status == "error"
    assert not_found.error["code"] == "not_found"


def test_malwarebazaar_hash_lookup_missing_inputs() -> None:
    fn = MalwareBazaarHashLookupFunction()

    assert fn.run({"results": {}, "config": {}}, {}).error["code"] == "missing_hash_result"
    assert (
        fn.run(hash_context({"malwarebazaar": {"auth_key": "test"}}, ""), {}).error["code"]
        == "missing_sha256"
    )
    assert fn.run(hash_context(), {}).error["code"] == "missing_auth_key"


def test_malwarebazaar_download_sample_requires_confirmation() -> None:
    result = MalwareBazaarDownloadSampleFunction().run(
        {"config": {"malwarebazaar": {"auth_key": "test-key"}}},
        {"sha256_hash": SHA256},
    )

    assert result.status == "error"
    assert result.error["code"] == "download_not_confirmed"


def test_malwarebazaar_download_sample_mock_success(monkeypatch, tmp_path) -> None:
    content = b"MZ test sample"
    sha256 = hashlib.sha256(content).hexdigest()
    zip_bytes = BytesIO()
    with zipfile.ZipFile(zip_bytes, "w") as zf:
        zf.writestr("sample.exe", content)

    def fake_urlopen(request, timeout):
        fields = urllib.parse.parse_qs(request.data.decode("utf-8"))
        query = fields.get("query", [""])[0]
        if query == "get_info":
            return FakeResponse(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "sha256_hash": sha256,
                            "file_type": "exe",
                            "file_size": len(content),
                            "signature": "TestSig",
                            "tags": ["exe"],
                        }
                    ],
                }
            )
        if query == "get_file":
            return FakeBytesResponse(zip_bytes.getvalue())
        raise AssertionError(f"unexpected query: {query}")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mb_download_module.urllib.request, "urlopen", fake_urlopen)

    result = MalwareBazaarDownloadSampleFunction().run(
        {"config": {"malwarebazaar": {"auth_key": "test-key"}}},
        {
            "confirm_download": "I_UNDERSTAND_DOWNLOAD_MALWARE_SAMPLE",
            "sha256_hash": sha256,
        },
    )

    assert result.status == "success"
    sample_path = tmp_path / result.data["sample_path"]
    assert sample_path.read_bytes() == content
    assert result.data["sha256"] == sha256
    assert result.data["filename"] == f"{sha256}.exe"
    assert result.data["activate_sample_path"] is True
    assert result.data["source_metadata"]["signature"] == "TestSig"
    assert not (tmp_path / result.data["quarantine_dir"] / f"{sha256}.zip").exists()
    assert (tmp_path / result.data["quarantine_dir"] / "manifest.json").is_file()
    assert "test-key" not in json.dumps(result.data)


def test_malwarebazaar_download_sample_uses_batch_index_as_candidate_offset(
    monkeypatch,
    tmp_path,
) -> None:
    first_content = b"MZ first sample"
    second_content = b"MZ second sample"
    first_sha256 = hashlib.sha256(first_content).hexdigest()
    second_sha256 = hashlib.sha256(second_content).hexdigest()
    zip_bytes = BytesIO()
    with zipfile.ZipFile(zip_bytes, "w") as zf:
        zf.writestr("sample.exe", second_content)

    def fake_urlopen(request, timeout):
        fields = urllib.parse.parse_qs(request.data.decode("utf-8"))
        query = fields.get("query", [""])[0]
        if query == "get_recent":
            return FakeResponse(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "sha256_hash": first_sha256,
                            "file_type": "exe",
                            "file_size": len(first_content),
                            "signature": "First",
                            "tags": ["exe"],
                        },
                        {
                            "sha256_hash": second_sha256,
                            "file_type": "exe",
                            "file_size": len(second_content),
                            "signature": "Second",
                            "tags": ["exe"],
                        },
                    ],
                }
            )
        if query == "get_file":
            assert fields.get("sha256_hash", [""])[0] == second_sha256
            return FakeBytesResponse(zip_bytes.getvalue())
        raise AssertionError(f"unexpected query: {query}")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mb_download_module.urllib.request, "urlopen", fake_urlopen)

    result = MalwareBazaarDownloadSampleFunction().run(
        {"batch_index": 1, "config": {"malwarebazaar": {"auth_key": "test-key"}}},
        {"confirm_download": "I_UNDERSTAND_DOWNLOAD_MALWARE_SAMPLE"},
    )

    assert result.status == "success"
    assert result.data["sha256"] == second_sha256
    assert result.data["candidate_offset"] == 1
    assert (tmp_path / result.data["sample_path"]).read_bytes() == second_content


def test_virustotal_behaviour_summary_mock_success_and_errors(monkeypatch) -> None:
    monkeypatch.setattr(
        vt_behaviour_module.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse(
            {
                "data": {
                    "attributes": {
                        "command_executions": ["cmd.exe /c test"],
                        "dns_lookups": ["example.com"],
                    }
                }
            }
        ),
    )
    result = VirusTotalBehaviourSummaryFunction().run(
        hash_context({"virustotal": {"api_key": "test-key"}}),
        {},
    )
    assert result.status == "success"
    assert result.data["requires_human_confirmation"] is True
    assert result.data["command_executions"] == ["cmd.exe /c test"]

    monkeypatch.setattr(
        vt_behaviour_module.urllib.request,
        "urlopen",
        lambda request, timeout: (_ for _ in ()).throw(http_error(401)),
    )
    unauthorized = VirusTotalBehaviourSummaryFunction().run(
        hash_context({"virustotal": {"api_key": "test-key"}}),
        {},
    )
    assert unauthorized.status == "error"
    assert unauthorized.error["code"] == "unauthorized"
