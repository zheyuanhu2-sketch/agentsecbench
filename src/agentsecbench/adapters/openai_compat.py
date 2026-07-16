"""Shared strict helpers for OpenAI-compatible chat-completion adapters."""

from __future__ import annotations

from typing import Any

from agentsecbench.adapters.base import MODEL_ID_PATTERN, AdapterError, ModelRequest


def chat_completion_payload(model_id: str, request: ModelRequest) -> dict[str, Any]:
    return {
        "model": model_id,
        "messages": [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.user_prompt},
        ],
        "max_tokens": request.max_output_tokens,
        "stream": False,
        "temperature": 0,
    }


def parse_chat_completion_response(
    response: dict[str, Any],
    *,
    provider_name: str = "model endpoint",
) -> tuple[str, str, int, int]:
    try:
        choices = response["choices"]
        first_choice = choices[0]
        content = first_choice["message"]["content"]
        usage = response["usage"]
        input_tokens = usage["prompt_tokens"]
        output_tokens = usage["completion_tokens"]
        model_id = response["model"]
    except (KeyError, IndexError, TypeError) as error:
        raise AdapterError(f"{provider_name} returned an invalid response shape") from error

    if not isinstance(content, str) or not content or "\x00" in content:
        raise AdapterError(f"{provider_name} returned invalid model content")
    if not isinstance(model_id, str) or not MODEL_ID_PATTERN.fullmatch(model_id):
        raise AdapterError(f"{provider_name} returned an invalid model identifier")
    token_values = (input_tokens, output_tokens)
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in token_values
    ):
        raise AdapterError(f"{provider_name} returned invalid token accounting")
    return content, model_id, input_tokens, output_tokens
