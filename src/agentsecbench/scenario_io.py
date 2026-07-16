"""Versioned, bounded JSON input for synthetic external scenario catalogs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agentsecbench.models import (
    ActionProposal,
    FileRecord,
    Message,
    Scenario,
    TaskKind,
    TaskPolicy,
)
from agentsecbench.tools import MAX_VALUE_LENGTH
from agentsecbench.validation import (
    IDENTIFIER_PATTERN,
    KNOWN_TOOLS,
    CatalogValidationError,
    validate_catalog,
)

SCENARIO_SCHEMA_VERSION = "agentsecbench.scenario.v1"
DATA_CLASSIFICATION = "synthetic"
MAX_SCENARIO_FILE_BYTES = 2_097_152
MAX_EXTERNAL_SCENARIOS = 1_000


class ScenarioSchemaError(ValueError):
    """Raised when an external scenario catalog violates the input contract."""


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ScenarioSchemaError("scenario JSON contains duplicate keys")
        result[key] = value
    return result


def _exact_object(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ScenarioSchemaError(f"invalid {name} object")
    return value


def _string(value: object, name: str, *, maximum: int = MAX_VALUE_LENGTH) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > maximum:
        raise ScenarioSchemaError(f"invalid {name}")
    return value


def _identifier(value: object, name: str) -> str:
    identifier = _string(value, name, maximum=64)
    if not IDENTIFIER_PATTERN.fullmatch(identifier):
        raise ScenarioSchemaError(f"invalid {name}")
    return identifier


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ScenarioSchemaError(f"invalid {name}")
    return value


def _list(value: object, name: str, *, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ScenarioSchemaError(f"invalid {name}")
    return value


def _string_list(
    value: object,
    name: str,
    *,
    maximum_items: int,
    maximum_length: int = 256,
) -> tuple[str, ...]:
    items = _list(value, name, maximum=maximum_items)
    parsed = tuple(_string(item, name, maximum=maximum_length) for item in items)
    if len(parsed) != len(set(parsed)):
        raise ScenarioSchemaError(f"duplicate {name}")
    return parsed


def _parse_message(value: object) -> Message:
    data = _exact_object(
        value,
        frozenset({"message_id", "sender", "subject", "body", "trusted"}),
        "message",
    )
    return Message(
        message_id=_identifier(data["message_id"], "message identifier"),
        sender=_string(data["sender"], "message sender", maximum=254),
        subject=_string(data["subject"], "message subject", maximum=500),
        body=_string(data["body"], "message body"),
        trusted=_boolean(data["trusted"], "message trust flag"),
    )


def _parse_file(value: object) -> FileRecord:
    data = _exact_object(
        value,
        frozenset({"path", "content", "trusted"}),
        "file",
    )
    return FileRecord(
        path=_string(data["path"], "file path", maximum=256),
        content=_string(data["content"], "file content"),
        trusted=_boolean(data["trusted"], "file trust flag"),
    )


def _parse_arguments(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not value or len(value) > 8:
        raise ScenarioSchemaError("invalid action arguments")
    arguments: dict[str, str] = {}
    for key, argument in value.items():
        if not isinstance(key, str) or not IDENTIFIER_PATTERN.fullmatch(key.replace("_", "-")):
            raise ScenarioSchemaError("invalid action argument name")
        arguments[key] = _string(argument, "action argument")
    return arguments


def _parse_action(value: object) -> ActionProposal:
    data = _exact_object(
        value,
        frozenset({"action_id", "tool", "arguments", "derived_from", "required", "forbidden"}),
        "action",
    )
    tool = _string(data["tool"], "tool identifier", maximum=64)
    if tool not in KNOWN_TOOLS:
        raise ScenarioSchemaError("unknown action tool")
    derived_from = tuple(
        _identifier(item, "provenance identifier")
        for item in _list(data["derived_from"], "action provenance", maximum=32)
    )
    if len(derived_from) != len(set(derived_from)):
        raise ScenarioSchemaError("duplicate provenance identifier")
    return ActionProposal(
        action_id=_identifier(data["action_id"], "action identifier"),
        tool=tool,
        arguments=_parse_arguments(data["arguments"]),
        derived_from=derived_from,
        required=_boolean(data["required"], "required label"),
        forbidden=_boolean(data["forbidden"], "forbidden label"),
    )


def _parse_policy(value: object) -> TaskPolicy:
    data = _exact_object(
        value,
        frozenset(
            {
                "allowed_tools",
                "allowed_recipient_domains",
                "writable_path_prefixes",
                "approval_required_tools",
                "approved_action_ids",
            }
        ),
        "policy",
    )
    allowed_tools = frozenset(
        _string_list(data["allowed_tools"], "allowed tool", maximum_items=16, maximum_length=64)
    )
    approval_tools = frozenset(
        _string_list(
            data["approval_required_tools"],
            "approval tool",
            maximum_items=16,
            maximum_length=64,
        )
    )
    if not allowed_tools <= KNOWN_TOOLS or not approval_tools <= KNOWN_TOOLS:
        raise ScenarioSchemaError("policy references an unknown tool")
    approved_action_ids = tuple(
        _identifier(item, "approved action identifier")
        for item in _list(data["approved_action_ids"], "approved action identifiers", maximum=32)
    )
    if len(approved_action_ids) != len(set(approved_action_ids)):
        raise ScenarioSchemaError("duplicate approved action identifier")
    return TaskPolicy(
        allowed_tools=allowed_tools,
        allowed_recipient_domains=frozenset(
            _string_list(
                data["allowed_recipient_domains"],
                "recipient domain",
                maximum_items=64,
                maximum_length=253,
            )
        ),
        writable_path_prefixes=_string_list(
            data["writable_path_prefixes"],
            "writable path prefix",
            maximum_items=64,
        ),
        approval_required_tools=approval_tools,
        approved_action_ids=frozenset(approved_action_ids),
    )


def _parse_scenario(value: object) -> Scenario:
    data = _exact_object(
        value,
        frozenset(
            {
                "task_id",
                "kind",
                "goal",
                "messages",
                "files",
                "actions",
                "policy",
                "sensitive_values",
            }
        ),
        "scenario",
    )
    kind_value = _string(data["kind"], "task kind", maximum=16)
    try:
        kind = TaskKind(kind_value)
    except ValueError as error:
        raise ScenarioSchemaError("invalid task kind") from error
    return Scenario(
        task_id=_identifier(data["task_id"], "task identifier"),
        kind=kind,
        goal=_string(data["goal"], "task goal", maximum=500),
        messages=tuple(
            _parse_message(item) for item in _list(data["messages"], "messages", maximum=128)
        ),
        files=tuple(_parse_file(item) for item in _list(data["files"], "files", maximum=128)),
        actions=tuple(
            _parse_action(item) for item in _list(data["actions"], "actions", maximum=32)
        ),
        policy=_parse_policy(data["policy"]),
        sensitive_values=_string_list(
            data["sensitive_values"],
            "sensitive value",
            maximum_items=32,
            maximum_length=256,
        ),
    )


def parse_scenario_catalog(value: object) -> tuple[Scenario, ...]:
    """Parse and validate the exact external synthetic-scenario schema."""

    root = _exact_object(
        value,
        frozenset({"schema_version", "data_classification", "scenarios"}),
        "scenario catalog",
    )
    if root["schema_version"] != SCENARIO_SCHEMA_VERSION:
        raise ScenarioSchemaError("unsupported scenario schema version")
    if root["data_classification"] != DATA_CLASSIFICATION:
        raise ScenarioSchemaError("external scenario data must be classified as synthetic")
    raw_scenarios = _list(root["scenarios"], "scenario list", maximum=MAX_EXTERNAL_SCENARIOS)
    if not raw_scenarios:
        raise ScenarioSchemaError("scenario list must not be empty")
    scenarios = tuple(_parse_scenario(item) for item in raw_scenarios)
    try:
        validate_catalog(scenarios)
    except CatalogValidationError as error:
        raise ScenarioSchemaError(f"scenario catalog invariant failed: {error}") from error
    return scenarios


def _safe_input_path(raw_path: str | os.PathLike[str]) -> Path:
    path = Path(raw_path)
    if not str(path) or len(str(path)) > 4_096 or path.suffix.lower() != ".json":
        raise ScenarioSchemaError("scenario path must identify a JSON file")
    if not path.is_file() or path.is_symlink():
        raise ScenarioSchemaError("scenario path must be an existing regular file")
    return path


def load_scenario_catalog(raw_path: str | os.PathLike[str]) -> tuple[Scenario, ...]:
    """Load a bounded UTF-8 scenario file without includes or external references."""

    path = _safe_input_path(raw_path)
    size = path.stat().st_size
    if not 0 < size <= MAX_SCENARIO_FILE_BYTES:
        raise ScenarioSchemaError("scenario file size is invalid")
    try:
        decoded: Any = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ScenarioSchemaError) as error:
        raise ScenarioSchemaError("scenario file is not valid bounded UTF-8 JSON") from error
    return parse_scenario_catalog(decoded)


def scenario_catalog_dict(scenarios: tuple[Scenario, ...]) -> dict[str, object]:
    """Serialize validated scenarios into the stable external representation."""

    validate_catalog(scenarios)
    return {
        "schema_version": SCENARIO_SCHEMA_VERSION,
        "data_classification": DATA_CLASSIFICATION,
        "scenarios": [
            {
                "task_id": scenario.task_id,
                "kind": scenario.kind.value,
                "goal": scenario.goal,
                "messages": [
                    {
                        "message_id": message.message_id,
                        "sender": message.sender,
                        "subject": message.subject,
                        "body": message.body,
                        "trusted": message.trusted,
                    }
                    for message in scenario.messages
                ],
                "files": [
                    {
                        "path": record.path,
                        "content": record.content,
                        "trusted": record.trusted,
                    }
                    for record in scenario.files
                ],
                "actions": [
                    {
                        "action_id": action.action_id,
                        "tool": action.tool,
                        "arguments": dict(action.arguments),
                        "derived_from": list(action.derived_from),
                        "required": action.required,
                        "forbidden": action.forbidden,
                    }
                    for action in scenario.actions
                ],
                "policy": {
                    "allowed_tools": sorted(scenario.policy.allowed_tools),
                    "allowed_recipient_domains": sorted(scenario.policy.allowed_recipient_domains),
                    "writable_path_prefixes": list(scenario.policy.writable_path_prefixes),
                    "approval_required_tools": sorted(scenario.policy.approval_required_tools),
                    "approved_action_ids": sorted(scenario.policy.approved_action_ids),
                },
                "sensitive_values": list(scenario.sensitive_values),
            }
            for scenario in scenarios
        ],
    }
