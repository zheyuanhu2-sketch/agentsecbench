"""Provider-neutral model contracts with fail-closed resource accounting."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}")
MODEL_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


class AdapterError(RuntimeError):
    """Safe adapter failure whose message must not contain prompts or credentials."""


class BudgetExceeded(AdapterError):
    """Raised before a request can exceed a configured resource boundary."""


@dataclass(frozen=True)
class BudgetLimits:
    max_requests: int = 50
    max_input_bytes_per_request: int = 65_536
    max_total_input_bytes: int = 1_048_576
    max_output_tokens_per_request: int = 1_024
    max_total_tokens: int = 200_000
    max_response_bytes: int = 262_144
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        integer_values = (
            self.max_requests,
            self.max_input_bytes_per_request,
            self.max_total_input_bytes,
            self.max_output_tokens_per_request,
            self.max_total_tokens,
            self.max_response_bytes,
        )
        if any(value <= 0 for value in integer_values):
            raise ValueError("budget limits must be positive")
        if not 0.1 <= self.timeout_seconds <= 120.0:
            raise ValueError("timeout must be between 0.1 and 120 seconds")


@dataclass(frozen=True)
class ModelRequest:
    request_id: str
    system_prompt: str
    user_prompt: str
    max_output_tokens: int = 256

    def __post_init__(self) -> None:
        if not REQUEST_ID_PATTERN.fullmatch(self.request_id):
            raise ValueError("invalid request identifier")
        if not self.system_prompt or "\x00" in self.system_prompt:
            raise ValueError("invalid system prompt")
        if not self.user_prompt or "\x00" in self.user_prompt:
            raise ValueError("invalid user prompt")
        if self.max_output_tokens <= 0:
            raise ValueError("max output tokens must be positive")

    @property
    def input_bytes(self) -> int:
        return len(self.system_prompt.encode("utf-8")) + len(self.user_prompt.encode("utf-8"))


@dataclass(frozen=True)
class ModelResponse:
    request_id: str
    adapter_id: str
    model_id: str
    content: str
    input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        if not REQUEST_ID_PATTERN.fullmatch(self.request_id):
            raise ValueError("invalid response request identifier")
        if not MODEL_ID_PATTERN.fullmatch(self.adapter_id):
            raise ValueError("invalid adapter identifier")
        if not MODEL_ID_PATTERN.fullmatch(self.model_id):
            raise ValueError("invalid model identifier")
        if not self.content or "\x00" in self.content:
            raise ValueError("invalid model content")
        if self.input_tokens < 0 or self.output_tokens < 0:
            raise ValueError("token usage must be non-negative")


@dataclass(frozen=True)
class BudgetReservation:
    input_bytes: int
    max_output_tokens: int


@dataclass
class BudgetLedger:
    """Single-run, single-threaded request and token accounting."""

    limits: BudgetLimits
    requests_used: int = 0
    input_bytes_used: int = 0
    tokens_used: int = 0

    def reserve(self, request: ModelRequest) -> BudgetReservation:
        if request.input_bytes > self.limits.max_input_bytes_per_request:
            raise BudgetExceeded("request input exceeds the per-request budget")
        if request.max_output_tokens > self.limits.max_output_tokens_per_request:
            raise BudgetExceeded("request output exceeds the per-request budget")
        if self.requests_used + 1 > self.limits.max_requests:
            raise BudgetExceeded("request count budget exhausted")
        if self.input_bytes_used + request.input_bytes > self.limits.max_total_input_bytes:
            raise BudgetExceeded("total input budget exhausted")
        conservative_token_ceiling = request.input_bytes + request.max_output_tokens
        if self.tokens_used + conservative_token_ceiling > self.limits.max_total_tokens:
            raise BudgetExceeded("total token budget exhausted")

        self.requests_used += 1
        self.input_bytes_used += request.input_bytes
        return BudgetReservation(request.input_bytes, request.max_output_tokens)

    def settle(
        self,
        reservation: BudgetReservation,
        *,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        if input_tokens < 0 or output_tokens < 0:
            raise AdapterError("provider returned invalid token accounting")
        if output_tokens > reservation.max_output_tokens:
            raise BudgetExceeded("provider exceeded the reserved output budget")
        if input_tokens + output_tokens > reservation.input_bytes + reservation.max_output_tokens:
            raise BudgetExceeded("provider usage exceeded the conservative token reservation")
        if self.tokens_used + input_tokens + output_tokens > self.limits.max_total_tokens:
            raise BudgetExceeded("total token budget exhausted")
        self.tokens_used += input_tokens + output_tokens


class ModelAdapter(Protocol):
    adapter_id: str
    model_id: str

    def complete(self, request: ModelRequest, budget: BudgetLedger) -> ModelResponse: ...
