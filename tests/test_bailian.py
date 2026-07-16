from __future__ import annotations

from typing import Any

import pytest

from agentsecbench.adapters.bailian import BailianChatAdapter, BailianChatConfig
from agentsecbench.adapters.base import (
    AdapterError,
    BudgetLedger,
    BudgetLimits,
    ModelRequest,
    ModelResponse,
)


class _StubTransport:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.payload: dict[str, Any] | None = None

    def post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.payload = payload
        return self.response


def _valid_response(content: str = "AGENTSECBENCH_BAILIAN_OK") -> dict[str, Any]:
    return {
        "id": "synthetic-completion",
        "model": "qwen-plus",
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
    }


def _config() -> BailianChatConfig:
    return BailianChatConfig(
        base_url=("https://workspace-placeholder.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"),
        model_id="qwen-plus",
    )


def _request() -> ModelRequest:
    return ModelRequest(
        request_id="bailian-test-0001",
        system_prompt="Use synthetic data only.",
        user_prompt="Return the expected marker.",
        max_output_tokens=32,
    )


def test_bailian_adapter_builds_bounded_chat_completion_request() -> None:
    transport = _StubTransport(_valid_response())
    limits = BudgetLimits(max_requests=1, max_output_tokens_per_request=32)
    adapter = BailianChatAdapter(_config(), limits, transport=transport)

    response = adapter.complete(_request(), BudgetLedger(limits))

    assert response.model_id == "qwen-plus"
    assert response.content == "AGENTSECBENCH_BAILIAN_OK"
    assert transport.payload == {
        "model": "qwen-plus",
        "messages": [
            {"role": "system", "content": "Use synthetic data only."},
            {"role": "user", "content": "Return the expected marker."},
        ],
        "max_tokens": 32,
        "stream": False,
        "temperature": 0,
    }


@pytest.mark.parametrize(
    "base_url",
    (
        "https://example.com/compatible-mode/v1",
        "https://workspace.cn-beijing.maas.aliyuncs.com/api/v1",
        "http://workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
        "https://workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1?redirect=1",
    ),
)
def test_bailian_config_rejects_non_official_or_wrong_protocol(base_url: str) -> None:
    with pytest.raises(ValueError):
        BailianChatConfig(base_url=base_url)


@pytest.mark.parametrize(
    "response",
    (
        {},
        {"choices": []},
        {
            "model": "qwen-plus",
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": True, "completion_tokens": 1},
        },
        {
            "model": "invalid model with spaces",
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        },
    ),
)
def test_bailian_adapter_rejects_invalid_response_shapes(response: dict[str, Any]) -> None:
    limits = BudgetLimits(max_requests=1, max_output_tokens_per_request=32)
    adapter = BailianChatAdapter(_config(), limits, transport=_StubTransport(response))

    with pytest.raises(AdapterError, match="Bailian returned"):
        adapter.complete(_request(), BudgetLedger(limits))


def test_bailian_environment_config_requires_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTSECBENCH_BAILIAN_BASE_URL", raising=False)

    with pytest.raises(AdapterError, match="base URL"):
        BailianChatConfig.from_environment()


def test_bailian_smoke_cli_requires_explicit_network_approval() -> None:
    from agentsecbench.cli import main

    with pytest.raises(SystemExit) as captured:
        main(("bailian-smoke",))

    assert captured.value.code == 2


def test_bailian_smoke_cli_prints_metadata_not_content(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agentsecbench.cli import main

    class _FakeLiveAdapter:
        def complete(self, request: ModelRequest, budget: BudgetLedger) -> ModelResponse:
            del budget
            return ModelResponse(
                request_id=request.request_id,
                adapter_id="bailian.chat-completions",
                model_id="qwen-plus",
                content="AGENTSECBENCH_BAILIAN_OK",
                input_tokens=10,
                output_tokens=5,
            )

    monkeypatch.setattr(
        BailianChatAdapter,
        "from_environment",
        classmethod(lambda _cls, _limits: _FakeLiveAdapter()),
    )

    assert main(("bailian-smoke", "--approve-network")) == 0
    output = capsys.readouterr().out
    assert "Expected content: True" in output
    assert "AGENTSECBENCH_BAILIAN_OK" not in output
