"""HTTP JSON transport restricted to literal loopback addresses."""

from __future__ import annotations

import http.client
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit

from agentsecbench.adapters.base import AdapterError, BudgetLimits
from agentsecbench.adapters.transport import ENV_NAME_PATTERN, MAX_REQUEST_BYTES

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
MIN_LOCAL_PORT = 1_024
MAX_LOCAL_PORT = 65_535


@dataclass(frozen=True)
class LoopbackJsonTransportConfig:
    endpoint: str
    api_key_env: str = "AGENTSECBENCH_LOCAL_API_KEY"

    def __post_init__(self) -> None:
        parsed = _validated_loopback_endpoint(self.endpoint)
        if not ENV_NAME_PATTERN.fullmatch(self.api_key_env):
            raise ValueError("invalid local API-key environment variable name")
        object.__setattr__(self, "endpoint", parsed.geturl())


def _validated_loopback_endpoint(endpoint: str) -> SplitResult:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http":
        raise ValueError("local model endpoint must use loopback HTTP")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("local model endpoint contains forbidden URL components")
    if parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError("local model endpoint must use a literal loopback address")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("local model endpoint port is invalid") from error
    if port is None or not MIN_LOCAL_PORT <= port <= MAX_LOCAL_PORT:
        raise ValueError("local model endpoint must use an explicit unprivileged port")
    if not parsed.path.startswith("/") or ".." in parsed.path.split("/"):
        raise ValueError("local model endpoint path is invalid")
    return parsed


class LoopbackJsonTransport:
    """One-shot loopback POST with no DNS, proxy, redirect, or retry surface."""

    def __init__(self, config: LoopbackJsonTransportConfig, limits: BudgetLimits) -> None:
        self._config = config
        self._limits = limits
        self._endpoint = _validated_loopback_endpoint(config.endpoint)
        hostname = self._endpoint.hostname
        port = self._endpoint.port
        if hostname is None or port is None:
            raise ValueError("local model endpoint is incomplete")
        self._hostname = hostname
        self._port = port

    def post_json(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        api_key = os.environ.get(self._config.api_key_env, "agentsecbench-local")
        if not 1 <= len(api_key) <= 4_096 or "\x00" in api_key:
            raise AdapterError("local model API credential is invalid")
        try:
            request_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        except (TypeError, ValueError) as error:
            raise AdapterError("local model request is not JSON serializable") from error
        if len(request_body) > MAX_REQUEST_BYTES:
            raise AdapterError("local model request exceeds the transport-size limit")

        connection = http.client.HTTPConnection(
            self._hostname,
            port=self._port,
            timeout=self._limits.timeout_seconds,
        )
        try:
            connection.request(
                "POST",
                self._endpoint.path,
                body=request_body,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "agentsecbench/local",
                },
            )
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise AdapterError("local model endpoint returned a non-success status")
            content_type = response.getheader("Content-Type", "").lower()
            if "application/json" not in content_type:
                raise AdapterError("local model endpoint returned an unsupported content type")
            response_body = response.read(self._limits.max_response_bytes + 1)
            if len(response_body) > self._limits.max_response_bytes:
                raise AdapterError("local model response exceeds the response-size budget")
        except AdapterError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise AdapterError("local model transport failed") from error
        finally:
            connection.close()

        try:
            decoded = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdapterError("local model endpoint returned invalid JSON") from error
        if not isinstance(decoded, dict):
            raise AdapterError("local model endpoint returned an invalid JSON shape")
        return decoded
