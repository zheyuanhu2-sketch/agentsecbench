from __future__ import annotations

import json
from typing import Any

import pytest

from agentsecbench.adapters import (
    AdapterError,
    BudgetLedger,
    BudgetLimits,
    LocalChatAdapter,
    LocalChatConfig,
    LoopbackJsonTransport,
    LoopbackJsonTransportConfig,
    ModelRequest,
)


class _StubTransport:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.payload: dict[str, Any] | None = None

    def post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.payload = payload
        return self.response


def _request() -> ModelRequest:
    return ModelRequest(
        request_id="local-test-0001",
        system_prompt="Use synthetic data only.",
        user_prompt="Return exactly LOCAL_OK.",
        max_output_tokens=32,
    )


def _response() -> dict[str, Any]:
    return {
        "model": "qwen3:4b",
        "choices": [{"message": {"content": "LOCAL_OK"}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 3},
    }


def test_local_config_accepts_only_exact_loopback_openai_base() -> None:
    config = LocalChatConfig(model_id="qwen3:4b")
    ipv6 = LocalChatConfig(model_id="model-local", base_url="http://[::1]:1234/v1/")

    assert config.endpoint == "http://127.0.0.1:11434/v1/chat/completions"
    assert ipv6.endpoint == "http://[::1]:1234/v1/chat/completions"


@pytest.mark.parametrize(
    "base_url",
    (
        "https://127.0.0.1:11434/v1",
        "http://localhost:11434/v1",
        "http://0.0.0.0:11434/v1",
        "http://192.168.1.10:11434/v1",
        "http://127.0.0.1/v1",
        "http://127.0.0.1:80/v1",
        "http://user:pass@127.0.0.1:11434/v1",
        "http://127.0.0.1:11434/v1?target=remote",
        "http://127.0.0.1:11434/api",
    ),
)
def test_local_config_rejects_non_loopback_dns_privileged_and_malformed_urls(
    base_url: str,
) -> None:
    with pytest.raises(ValueError):
        LocalChatConfig(model_id="qwen3:4b", base_url=base_url)


def test_local_config_from_environment_requires_model_and_defaults_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENTSECBENCH_LOCAL_MODEL", raising=False)
    with pytest.raises(AdapterError, match="identifier"):
        LocalChatConfig.from_environment()

    monkeypatch.setenv("AGENTSECBENCH_LOCAL_MODEL", "qwen3:4b")
    config = LocalChatConfig.from_environment()
    assert config.base_url == "http://127.0.0.1:11434/v1"


def test_local_adapter_uses_shared_strict_chat_completion_contract() -> None:
    limits = BudgetLimits(max_requests=1, max_output_tokens_per_request=32)
    transport = _StubTransport(_response())
    adapter = LocalChatAdapter(LocalChatConfig(model_id="qwen3:4b"), limits, transport=transport)

    response = adapter.complete(_request(), BudgetLedger(limits))

    assert response.adapter_id == "local.openai-compatible"
    assert response.model_id == "qwen3:4b"
    assert response.content == "LOCAL_OK"
    assert transport.payload is not None
    assert transport.payload["temperature"] == 0
    assert transport.payload["stream"] is False
    assert transport.payload["messages"][0]["role"] == "system"


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.body = body
        self.status = status
        self.content_type = content_type

    def getheader(self, name: str, default: str = "") -> str:
        return self.content_type if name.lower() == "content-type" else default

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class _FakeConnection:
    next_response = _FakeResponse(b'{"ok":true}')
    last_request: tuple[str, str, bytes, dict[str, str]] | None = None
    closed = False

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        type(self).closed = False

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        type(self).last_request = (method, path, body, headers)

    def getresponse(self) -> _FakeResponse:
        return type(self).next_response

    def close(self) -> None:
        type(self).closed = True


def _transport(
    monkeypatch: pytest.MonkeyPatch, *, max_response_bytes: int = 1_024
) -> LoopbackJsonTransport:
    from agentsecbench.adapters import loopback as loopback_module

    monkeypatch.setattr(loopback_module.http.client, "HTTPConnection", _FakeConnection)
    config = LoopbackJsonTransportConfig(endpoint="http://127.0.0.1:11434/v1/chat/completions")
    return LoopbackJsonTransport(config, BudgetLimits(max_response_bytes=max_response_bytes))


def test_loopback_transport_posts_directly_without_dns_proxy_or_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeConnection.next_response = _FakeResponse(b'{"ok":true}')
    monkeypatch.delenv("AGENTSECBENCH_LOCAL_API_KEY", raising=False)
    transport = _transport(monkeypatch)

    response = transport.post_json({"model": "qwen3:4b"})

    assert response == {"ok": True}
    assert _FakeConnection.last_request is not None
    method, path, body, headers = _FakeConnection.last_request
    assert method == "POST"
    assert path == "/v1/chat/completions"
    assert json.loads(body) == {"model": "qwen3:4b"}
    assert headers["Authorization"] == "Bearer agentsecbench-local"
    assert _FakeConnection.closed is True


@pytest.mark.parametrize(
    ("response", "message"),
    (
        (_FakeResponse(b"{}", status=302), "non-success"),
        (_FakeResponse(b"{}", content_type="text/plain"), "content type"),
        (_FakeResponse(b"not-json"), "invalid JSON"),
        (_FakeResponse(b"[]"), "invalid JSON shape"),
    ),
)
def test_loopback_transport_fails_closed_for_bad_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: _FakeResponse,
    message: str,
) -> None:
    _FakeConnection.next_response = response
    transport = _transport(monkeypatch)

    with pytest.raises(AdapterError, match=message):
        transport.post_json({"model": "qwen3:4b"})


def test_loopback_transport_rejects_invalid_optional_key_and_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTSECBENCH_LOCAL_API_KEY", "")
    transport = _transport(monkeypatch)
    with pytest.raises(AdapterError, match="credential"):
        transport.post_json({"model": "qwen3:4b"})

    monkeypatch.delenv("AGENTSECBENCH_LOCAL_API_KEY", raising=False)
    _FakeConnection.next_response = _FakeResponse(b"12345")
    transport = _transport(monkeypatch, max_response_bytes=4)
    with pytest.raises(AdapterError, match="response-size"):
        transport.post_json({"model": "qwen3:4b"})
