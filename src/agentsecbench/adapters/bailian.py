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
        payload: dict[str, Any] = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "max_tokens": request.max_output_tokens,
            "stream": False,
            "temperature": 0,
        }
        response = self._transport.post_json(payload)
        content, response_model, input_tokens, output_tokens = _parse_response(response)
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


def _parse_response(response: dict[str, Any]) -> tuple[str, str, int, int]:
    try:
        choices = response["choices"]
        first_choice = choices[0]
        content = first_choice["message"]["content"]
        usage = response["usage"]
        input_tokens = usage["prompt_tokens"]
        output_tokens = usage["completion_tokens"]
        model_id = response["model"]
    except (KeyError, IndexError, TypeError) as error:
        raise AdapterError("Bailian returned an invalid response shape") from error

    if not isinstance(content, str) or not content or "\x00" in content:
        raise AdapterError("Bailian returned invalid model content")
    if not isinstance(model_id, str) or not MODEL_ID_PATTERN.fullmatch(model_id):
        raise AdapterError("Bailian returned an invalid model identifier")
    token_values = (input_tokens, output_tokens)
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in token_values
    ):
        raise AdapterError("Bailian returned invalid token accounting")
    return content, model_id, input_tokens, output_tokens
