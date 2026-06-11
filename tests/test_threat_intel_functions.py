import json
import socket
import urllib.error

from tests.module_function_helpers import reverse_function_module

mb_module = reverse_function_module("malwarebazaar_hash_lookup.py")
vt_behaviour_module = reverse_function_module("virustotal_behaviour_summary.py")
vt_module = reverse_function_module("virustotal_hash_lookup.py")

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
