"""Small explicit-secret redactor for safe diagnostics and future artifacts."""

from __future__ import annotations

from dataclasses import dataclass

REDACTION_MARKER = "<redacted>"


@dataclass(frozen=True)
class SecretRedactor:
    secrets: tuple[str, ...]

    def __post_init__(self) -> None:
        normalized = tuple(sorted(set(self.secrets), key=len, reverse=True))
        if len(normalized) > 32:
            raise ValueError("too many redaction secrets")
        if any(len(secret) < 8 or len(secret) > 4_096 for secret in normalized):
            raise ValueError("redaction secrets must contain 8 to 4096 characters")
        object.__setattr__(self, "secrets", normalized)

    def redact(self, text: str) -> str:
        redacted = text
        for secret in self.secrets:
            redacted = redacted.replace(secret, REDACTION_MARKER)
        return redacted
