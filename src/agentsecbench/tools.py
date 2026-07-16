"""In-memory tools with no network, subprocess, or host-filesystem effects."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from agentsecbench.models import FileRecord, Message, PolicyAction, ToolOutput

MAX_VALUE_LENGTH = 16_384


class ToolExecutionError(ValueError):
    """Raised when an action violates the deterministic tool contract."""


def safe_relative_path(raw_path: str) -> str:
    """Normalize a synthetic POSIX path and reject traversal or absolute paths."""

    if not raw_path or len(raw_path) > 256 or "\\" in raw_path:
        raise ToolExecutionError("invalid synthetic path")
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ToolExecutionError("invalid synthetic path")
    return path.as_posix()


def _required(arguments: Mapping[str, str], key: str) -> str:
    value = arguments.get(key)
    if value is None or not value or len(value) > MAX_VALUE_LENGTH:
        raise ToolExecutionError(f"invalid {key}")
    return value


@dataclass
class InMemoryEnvironment:
    """Per-scenario isolated state."""

    messages: dict[str, Message]
    files: dict[str, FileRecord]
    sent_mail: list[tuple[str, str, str]] = field(default_factory=list)

    @classmethod
    def from_records(
        cls, messages: tuple[Message, ...], files: tuple[FileRecord, ...]
    ) -> InMemoryEnvironment:
        return cls(
            messages={message.message_id: message for message in messages},
            files={safe_relative_path(record.path): record for record in files},
        )

    def execute(self, action: PolicyAction) -> ToolOutput:
        handlers = {
            "mail.read": self._mail_read,
            "mail.send": self._mail_send,
            "file.read": self._file_read,
            "file.write": self._file_write,
        }
        handler = handlers.get(action.tool)
        if handler is None:
            raise ToolExecutionError("unknown tool")
        return handler(action.arguments)

    def _mail_read(self, arguments: Mapping[str, str]) -> ToolOutput:
        message_id = _required(arguments, "message_id")
        message = self.messages.get(message_id)
        if message is None:
            raise ToolExecutionError("unknown message")
        return ToolOutput(value=message.body, tainted=not message.trusted)

    def _mail_send(self, arguments: Mapping[str, str]) -> ToolOutput:
        recipient = _required(arguments, "recipient")
        subject = _required(arguments, "subject")
        body = _required(arguments, "body")
        if recipient.count("@") != 1:
            raise ToolExecutionError("invalid recipient")
        self.sent_mail.append((recipient, subject, body))
        return ToolOutput(value="mail accepted by synthetic outbox", tainted=False)

    def _file_read(self, arguments: Mapping[str, str]) -> ToolOutput:
        path = safe_relative_path(_required(arguments, "path"))
        record = self.files.get(path)
        if record is None:
            raise ToolExecutionError("unknown file")
        return ToolOutput(value=record.content, tainted=not record.trusted)

    def _file_write(self, arguments: Mapping[str, str]) -> ToolOutput:
        path = safe_relative_path(_required(arguments, "path"))
        content = _required(arguments, "content")
        self.files[path] = FileRecord(path=path, content=content, trusted=True)
        return ToolOutput(value="file written in synthetic store", tainted=False)
