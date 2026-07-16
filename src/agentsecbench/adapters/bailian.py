"""Alibaba Cloud Model Studio Chat Completions adapter."""

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
from agentsecbench.adapters.openai_compat import (
    chat_completion_payload,
    parse_chat_completion_response,
)
from agentsecbench.adapters.transport import SecureJsonTransport, SecureJsonTransportConfig

BAILIAN_BASE_URL_ENV = "AGENTSECBENCH_BAILIAN_BASE_URL"
BAILIAN_API_KEY_ENV = "AGENTSECBENCH_BAILIAN_API_KEY"
BAILIAN_MODEL_ENV = "AGENTSECBENCH_BAILIAN_MODEL"
DEFAULT_BAILIAN_MODEL = "qwen-plus"
EXPECTED_BASE_PATH = "/compatible-mode/v1"


class _JsonTransport(Protocol):
    def post_json(self, payload: dict[str, Any]) -> dict[str, Any]: ...


def _is_official_bailian_host(hostname: str) -> bool:
    return hostname in {
        "dashscope.aliyuncs.com",
        "dashscope-intl.aliyuncs.com",
        "dashscope-us.aliyuncs.com",
    } or hostname.endswith(".maas.aliyuncs.com")


@dataclass(frozen=True)
class BailianChatConfig:
    base_url: str
    model_id: str = DEFAULT_BAILIAN_MODEL
    api_key_env: str = BAILIAN_API_KEY_ENV

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url.rstrip("/"))
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        if not _is_official_bailian_host(hostname):
            raise ValueError("Bailian endpoint must use an official Alibaba Cloud host")
        if parsed.path != EXPECTED_BASE_PATH:
            raise ValueError("Bailian base URL must end at the compatible-mode v1 path")
        if not MODEL_ID_PATTERN.fullmatch(self.model_id):
            raise ValueError("invalid Bailian model identifier")
        endpoint = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                f"{EXPECTED_BASE_PATH}/chat/completions",
                parsed.query,
                parsed.fragment,
            )
        )
        SecureJsonTransportConfig(
            endpoint=endpoint,
            allowed_hosts=frozenset({hostname}),
            api_key_env=self.api_key_env,
        )
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    @classmethod
    def from_environment(cls) -> BailianChatConfig:
        base_url = os.environ.get(BAILIAN_BASE_URL_ENV, "")
        model_id = os.environ.get(BAILIAN_MODEL_ENV, DEFAULT_BAILIAN_MODEL)
        if not base_url:
            raise AdapterError("Bailian base URL is unavailable")
        return cls(base_url=base_url, model_id=model_id)


class BailianChatAdapter:
    adapter_id = "bailian.chat-completions"

    def __init__(
        self,
        config: BailianChatConfig,
        limits: BudgetLimits,
        *,
        transport: _JsonTransport | None = None,
    ) -> None:
        self.config = config
        self.model_id = config.model_id
        hostname = urlsplit(config.endpoint).hostname
        if hostname is None:
            raise ValueError("Bailian endpoint hostname is unavailable")
        transport_config = SecureJsonTransportConfig(
            endpoint=config.endpoint,
            allowed_hosts=frozenset({hostname}),
            api_key_env=config.api_key_env,
        )
        self._transport = transport or SecureJsonTransport(transport_config, limits)

    @classmethod
    def from_environment(cls, limits: BudgetLimits) -> BailianChatAdapter:
        return cls(BailianChatConfig.from_environment(), limits)

    def complete(self, request: ModelRequest, budget: BudgetLedger) -> ModelResponse:
        reservation = budget.reserve(request)
        payload = chat_completion_payload(self.model_id, request)
        response = self._transport.post_json(payload)
        content, response_model, input_tokens, output_tokens = parse_chat_completion_response(
            response, provider_name="Bailian"
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
