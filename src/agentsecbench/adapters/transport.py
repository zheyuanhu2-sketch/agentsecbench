"""HTTPS-only JSON transport with explicit egress and response boundaries."""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit

from agentsecbench.adapters.base import AdapterError, BudgetLimits

ENV_NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
MAX_REQUEST_BYTES = 262_144


@dataclass(frozen=True)
class SecureJsonTransportConfig:
    endpoint: str
    allowed_hosts: frozenset[str]
    api_key_env: str

    def __post_init__(self) -> None:
        parsed = _validated_endpoint(self.endpoint, self.allowed_hosts)
        if not ENV_NAME_PATTERN.fullmatch(self.api_key_env):
            raise ValueError("invalid API-key environment variable name")
        object.__setattr__(self, "endpoint", parsed.geturl())
        object.__setattr__(
            self,
            "allowed_hosts",
            frozenset(host.lower() for host in self.allowed_hosts),
        )


def _validated_endpoint(endpoint: str, allowed_hosts: frozenset[str]) -> SplitResult:
    if not allowed_hosts or any(not host or "*" in host or "/" in host for host in allowed_hosts):
        raise ValueError("allowed hosts must be explicit hostnames")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https":
        raise ValueError("model endpoint must use HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("model endpoint contains forbidden URL components")
    if parsed.port not in {None, 443}:
        raise ValueError("model endpoint must use the standard HTTPS port")
    if not parsed.hostname or parsed.hostname.lower() not in {
        host.lower() for host in allowed_hosts
    }:
        raise ValueError("model endpoint host is not allowlisted")
    if not parsed.path.startswith("/") or ".." in parsed.path.split("/"):
        raise ValueError("model endpoint path is invalid")
    try:
        parsed.hostname.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("model endpoint hostname must be ASCII") from error
    return parsed


class SecureJsonTransport:
    """One-shot POST transport: no redirects, retries, proxies, or response logging."""

    def __init__(self, config: SecureJsonTransportConfig, limits: BudgetLimits) -> None:
        self._config = config
        self._limits = limits
        self._endpoint = _validated_endpoint(config.endpoint, config.allowed_hosts)
        hostname = self._endpoint.hostname
        if hostname is None:
            raise ValueError("model endpoint hostname is unavailable")
        self._hostname = hostname

    def post_json(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        api_key = os.environ.get(self._config.api_key_env)
        if not api_key or len(api_key) < 8 or len(api_key) > 4_096:
            raise AdapterError("model API credential is unavailable")

        try:
            request_body = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise AdapterError("model request is not JSON serializable") from error
        if len(request_body) > MAX_REQUEST_BYTES:
            raise AdapterError("model request exceeds the transport-size limit")

        connection = http.client.HTTPSConnection(
            self._hostname,
            port=443,
            timeout=self._limits.timeout_seconds,
            context=ssl.create_default_context(),
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
                    "User-Agent": "agentsecbench/0.2",
                },
            )
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise AdapterError("model endpoint returned a non-success status")
            content_type = response.getheader("Content-Type", "").lower()
            if "application/json" not in content_type:
                raise AdapterError("model endpoint returned an unsupported content type")
            response_body = response.read(self._limits.max_response_bytes + 1)
            if len(response_body) > self._limits.max_response_bytes:
                raise AdapterError("model response exceeds the response-size budget")
        except AdapterError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise AdapterError("model transport failed") from error
        finally:
            connection.close()

        try:
            decoded = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdapterError("model endpoint returned invalid JSON") from error
        if not isinstance(decoded, dict):
            raise AdapterError("model endpoint returned an invalid JSON shape")
        return decoded
