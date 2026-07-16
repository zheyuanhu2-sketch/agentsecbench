"""Loopback-only OpenAI-compatible local model adapter."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from agentsecbench.adapters.base import (
    MODEL_ID_PATTERN,
    AdapterError,
    BudgetLedger,
    BudgetLimits,
    ModelRequest,
    ModelResponse,
)
from agentsecbench.adapters.loopback import (
    LoopbackJsonTransport,
    LoopbackJsonTransportConfig,
)
from agentsecbench.adapters.openai_compat import (
    chat_completion_payload,
    parse_chat_completion_response,
)

LOCAL_BASE_URL_ENV = "AGENTSECBENCH_LOCAL_BASE_URL"
LOCAL_MODEL_ENV = "AGENTSECBENCH_LOCAL_MODEL"
LOCAL_API_KEY_ENV = "AGENTSECBENCH_LOCAL_API_KEY"
DEFAULT_LOCAL_BASE_URL = "http://127.0.0.1:11434/v1"
EXPECTED_LOCAL_BASE_PATH = "/v1"


class _JsonTransport(Protocol):
    def post_json(self, payload: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class LocalChatConfig:
    model_id: str
    base_url: str = DEFAULT_LOCAL_BASE_URL
    api_key_env: str = LOCAL_API_KEY_ENV

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url.rstrip("/"))
        if parsed.path != EXPECTED_LOCAL_BASE_PATH:
            raise ValueError("local model base URL must end at /v1")
        if not MODEL_ID_PATTERN.fullmatch(self.model_id):
            raise ValueError("invalid local model identifier")
        endpoint = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                f"{EXPECTED_LOCAL_BASE_PATH}/chat/completions",
                parsed.query,
                parsed.fragment,
            )
        )
        LoopbackJsonTransportConfig(endpoint=endpoint, api_key_env=self.api_key_env)
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    @classmethod
    def from_environment(cls) -> LocalChatConfig:
        base_url = os.environ.get(LOCAL_BASE_URL_ENV, DEFAULT_LOCAL_BASE_URL)
        model_id = os.environ.get(LOCAL_MODEL_ENV, "")
        if not model_id:
            raise AdapterError("local model identifier is unavailable")
        return cls(base_url=base_url, model_id=model_id)


class LocalChatAdapter:
    adapter_id = "local.openai-compatible"

    def __init__(
        self,
        config: LocalChatConfig,
        limits: BudgetLimits,
        *,
        transport: _JsonTransport | None = None,
    ) -> None:
        self.config = config
        self.model_id = config.model_id
        transport_config = LoopbackJsonTransportConfig(
            endpoint=config.endpoint,
            api_key_env=config.api_key_env,
        )
        self._transport = transport or LoopbackJsonTransport(transport_config, limits)

    @classmethod
    def from_environment(cls, limits: BudgetLimits) -> LocalChatAdapter:
        return cls(LocalChatConfig.from_environment(), limits)

    def complete(self, request: ModelRequest, budget: BudgetLedger) -> ModelResponse:
        reservation = budget.reserve(request)
        response = self._transport.post_json(chat_completion_payload(self.model_id, request))
        content, response_model, input_tokens, output_tokens = parse_chat_completion_response(
            response, provider_name="local model endpoint"
        )
        budget.settle(
            reservation,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        return ModelResponse(
            request_id=request.request_id,
            adapter_id=self.adapter_id,
            model_id=response_model,
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
