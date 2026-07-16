"""Deterministic offline adapter for tests and benchmark plumbing."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from agentsecbench.adapters.base import (
    MODEL_ID_PATTERN,
    AdapterError,
    BudgetExceeded,
    BudgetLedger,
    ModelRequest,
    ModelResponse,
)


def _estimated_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


@dataclass(frozen=True)
class FakeModelAdapter:
    responses: Mapping[str, str]
    adapter_id: str = "offline.fake"
    model_id: str = "deterministic-v0"

    def __post_init__(self) -> None:
        if not MODEL_ID_PATTERN.fullmatch(self.adapter_id):
            raise ValueError("invalid fake adapter identifier")
        if not MODEL_ID_PATTERN.fullmatch(self.model_id):
            raise ValueError("invalid fake model identifier")
        object.__setattr__(self, "responses", MappingProxyType(dict(self.responses)))

    def complete(self, request: ModelRequest, budget: BudgetLedger) -> ModelResponse:
        reservation = budget.reserve(request)
        content = self.responses.get(request.request_id)
        if content is None:
            raise AdapterError("offline response is not configured")
        response_bytes = len(content.encode("utf-8"))
        if response_bytes > budget.limits.max_response_bytes:
            raise BudgetExceeded("offline response exceeds the response-size budget")

        input_tokens = _estimated_tokens(request.system_prompt + request.user_prompt)
        output_tokens = _estimated_tokens(content)
        budget.settle(
            reservation,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        return ModelResponse(
            request_id=request.request_id,
            adapter_id=self.adapter_id,
            model_id=self.model_id,
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
