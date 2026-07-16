from __future__ import annotations

import pytest

from agentsecbench.adapters.base import (
    AdapterError,
    BudgetExceeded,
    BudgetLedger,
    BudgetLimits,
    ModelRequest,
)
from agentsecbench.adapters.fake import FakeModelAdapter
from agentsecbench.adapters.redaction import REDACTION_MARKER, SecretRedactor
from agentsecbench.adapters.transport import SecureJsonTransport, SecureJsonTransportConfig


def _request(*, request_id: str = "request-0001", max_output_tokens: int = 32) -> ModelRequest:
    return ModelRequest(
        request_id=request_id,
        system_prompt="Use only synthetic benchmark data.",
        user_prompt="Return the next deterministic action.",
        max_output_tokens=max_output_tokens,
    )


def test_fake_adapter_is_deterministic_and_budgeted() -> None:
    request = _request()
    adapter = FakeModelAdapter({request.request_id: '{"action":"finish"}'})
    budget = BudgetLedger(BudgetLimits())

    response = adapter.complete(request, budget)

    assert response.content == '{"action":"finish"}'
    assert response.request_id == request.request_id
    assert budget.requests_used == 1
    assert budget.tokens_used == response.input_tokens + response.output_tokens


def test_fake_adapter_fails_closed_for_missing_or_oversized_response() -> None:
    request = _request()
    budget = BudgetLedger(BudgetLimits(max_requests=2, max_response_bytes=8))

    with pytest.raises(AdapterError, match="not configured"):
        FakeModelAdapter({}).complete(request, budget)

    with pytest.raises(BudgetExceeded, match="response-size"):
        FakeModelAdapter({request.request_id: "x" * 9}).complete(request, budget)


def test_budget_rejects_request_and_token_overruns() -> None:
    request = _request(max_output_tokens=33)
    budget = BudgetLedger(BudgetLimits(max_output_tokens_per_request=32))

    with pytest.raises(BudgetExceeded, match="per-request"):
        budget.reserve(request)

    small_request = _request(max_output_tokens=4)
    small_budget = BudgetLedger(BudgetLimits(max_requests=1, max_total_tokens=1_000))
    reservation = small_budget.reserve(small_request)
    with pytest.raises(BudgetExceeded, match="reserved output"):
        small_budget.settle(reservation, input_tokens=1, output_tokens=5)


@pytest.mark.parametrize("timeout", (0.0, 121.0))
def test_budget_rejects_unsafe_timeouts(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        BudgetLimits(timeout_seconds=timeout)


def test_redactor_replaces_longest_secrets_first() -> None:
    redactor = SecretRedactor(("abcdefgh", "abcdefgh-extra"))

    output = redactor.redact("token=abcdefgh-extra backup=abcdefgh")

    assert output == f"token={REDACTION_MARKER} backup={REDACTION_MARKER}"


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://model.example.test/v1/generate",
        "https://user:pass@model.example.test/v1/generate",
        "https://model.example.test:8443/v1/generate",
        "https://model.example.test/v1/generate?target=other",
        "https://other.example.test/v1/generate",
        "https://model.example.test/v1/../admin",
    ),
)
def test_transport_config_rejects_unsafe_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError):
        SecureJsonTransportConfig(
            endpoint=endpoint,
            allowed_hosts=frozenset({"model.example.test"}),
            api_key_env="AGENTSECBENCH_MODEL_API_KEY",
        )


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        self.body = body
        self.status = status
        self.content_type = content_type

    def getheader(self, name: str, default: str = "") -> str:
        return self.content_type if name.lower() == "content-type" else default

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class _FakeConnection:
    next_response = _FakeResponse(b'{"output":"ok"}')
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
) -> SecureJsonTransport:
    from agentsecbench.adapters import transport as transport_module

    monkeypatch.setattr(transport_module.http.client, "HTTPSConnection", _FakeConnection)
    monkeypatch.setenv("AGENTSECBENCH_MODEL_API_KEY", "x" * 24)
    config = SecureJsonTransportConfig(
        endpoint="https://model.example.test/v1/generate",
        allowed_hosts=frozenset({"model.example.test"}),
        api_key_env="AGENTSECBENCH_MODEL_API_KEY",
    )
    return SecureJsonTransport(config, BudgetLimits(max_response_bytes=max_response_bytes))


def test_transport_posts_json_without_redirect_or_proxy_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeConnection.next_response = _FakeResponse(b'{"output":"ok"}')
    transport = _transport(monkeypatch)

    response = transport.post_json({"prompt": "synthetic only"})

    assert response == {"output": "ok"}
    assert _FakeConnection.closed is True
    request = _FakeConnection.last_request
    assert request is not None
    method, path, body, headers = request
    assert (method, path) == ("POST", "/v1/generate")
    assert body == b'{"prompt":"synthetic only"}'
    assert headers["Authorization"] == f"Bearer {'x' * 24}"


@pytest.mark.parametrize(
    "response",
    (
        _FakeResponse(b'{"error":"do not expose this body"}', status=302),
        _FakeResponse(b"not-json"),
        _FakeResponse(b"[]"),
        _FakeResponse(b'{"ok":true}', content_type="text/plain"),
    ),
)
def test_transport_rejects_invalid_responses_without_echoing_body(
    monkeypatch: pytest.MonkeyPatch,
    response: _FakeResponse,
) -> None:
    _FakeConnection.next_response = response
    transport = _transport(monkeypatch)

    with pytest.raises(AdapterError) as captured:
        transport.post_json({"prompt": "synthetic"})

    assert "do not expose" not in str(captured.value)
    assert "synthetic" not in str(captured.value)
    assert _FakeConnection.closed is True


def test_transport_enforces_response_size(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeConnection.next_response = _FakeResponse(b"x" * 9)
    transport = _transport(monkeypatch, max_response_bytes=8)

    with pytest.raises(AdapterError, match="response-size"):
        transport.post_json({"prompt": "synthetic"})


def test_transport_requires_credential_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _transport(monkeypatch)
    monkeypatch.delenv("AGENTSECBENCH_MODEL_API_KEY")
    _FakeConnection.last_request = None

    with pytest.raises(AdapterError, match="credential"):
        transport.post_json({"prompt": "synthetic"})

    assert _FakeConnection.last_request is None
