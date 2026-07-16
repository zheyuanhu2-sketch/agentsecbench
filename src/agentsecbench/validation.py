"""Catalog invariants and reproducibility fingerprinting."""

from __future__ import annotations

import hashlib
import json
import re

from agentsecbench.models import Scenario, TaskKind
from agentsecbench.tools import MAX_VALUE_LENGTH, ToolExecutionError, safe_relative_path

KNOWN_TOOLS = frozenset({"mail.read", "mail.send", "file.read", "file.write"})
TOOL_ARGUMENT_KEYS = {
    "mail.read": frozenset({"message_id"}),
    "mail.send": frozenset({"recipient", "subject", "body"}),
    "file.read": frozenset({"path"}),
    "file.write": frozenset({"path", "content"}),
}
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
MAX_ACTIONS_PER_SCENARIO = 32


class CatalogValidationError(ValueError):
    """Raised when benchmark fixtures violate the evaluation contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CatalogValidationError(message)


def _validate_scenario(scenario: Scenario) -> None:
    _require(bool(IDENTIFIER_PATTERN.fullmatch(scenario.task_id)), "invalid task identifier")
    _require(0 < len(scenario.goal) <= 500, "invalid task goal")
    _require(
        0 < len(scenario.actions) <= MAX_ACTIONS_PER_SCENARIO,
        "invalid action count",
    )

    message_ids = [message.message_id for message in scenario.messages]
    _require(len(message_ids) == len(set(message_ids)), "duplicate message identifier")
    file_paths = [record.path for record in scenario.files]
    _require(len(file_paths) == len(set(file_paths)), "duplicate file path")
    for path in file_paths:
        try:
            safe_relative_path(path)
        except ToolExecutionError as error:
            raise CatalogValidationError("invalid catalog file path") from error

    action_ids = [action.action_id for action in scenario.actions]
    _require(len(action_ids) == len(set(action_ids)), "duplicate action identifier")
    seen: set[str] = set()
    for action in scenario.actions:
        _require(bool(IDENTIFIER_PATTERN.fullmatch(action.action_id)), "invalid action identifier")
        _require(action.tool in KNOWN_TOOLS, "unknown catalog tool")
        _require(
            set(action.arguments) == TOOL_ARGUMENT_KEYS[action.tool],
            "invalid catalog tool arguments",
        )
        _require(
            all(
                isinstance(value, str) and 0 < len(value) <= MAX_VALUE_LENGTH
                for value in action.arguments.values()
            ),
            "invalid catalog tool argument value",
        )
        _require(not (action.required and action.forbidden), "contradictory action labels")
        _require(set(action.derived_from) <= seen, "action provenance must reference prior actions")
        seen.add(action.action_id)

        if action.tool == "mail.read":
            _require(
                action.arguments["message_id"] in message_ids,
                "mail read references an unknown message",
            )
        elif action.tool == "mail.send":
            _require(action.arguments["recipient"].count("@") == 1, "invalid mail recipient")
        elif action.tool == "file.read":
            try:
                read_path = safe_relative_path(action.arguments["path"])
            except ToolExecutionError as error:
                raise CatalogValidationError("invalid read action path") from error
            _require(read_path in file_paths, "file read references an unknown file")
        elif action.tool == "file.write":
            try:
                safe_relative_path(action.arguments["path"])
            except ToolExecutionError as error:
                raise CatalogValidationError("invalid write action path") from error

    action_id_set = set(action_ids)
    _require(
        scenario.policy.approved_action_ids <= action_id_set,
        "approval references an unknown action",
    )
    _require(scenario.policy.allowed_tools <= KNOWN_TOOLS, "policy allows an unknown tool")
    _require(
        scenario.policy.approval_required_tools <= scenario.policy.allowed_tools,
        "approval requirement references a disallowed tool",
    )
    for domain in scenario.policy.allowed_recipient_domains:
        _require(bool(domain) and "@" not in domain and domain == domain.lower(), "invalid domain")
    for prefix in scenario.policy.writable_path_prefixes:
        _require(prefix.endswith("/"), "write prefix must end with a slash")
        try:
            safe_relative_path(prefix[:-1])
        except ToolExecutionError as error:
            raise CatalogValidationError("invalid write prefix") from error

    forbidden_actions = tuple(action for action in scenario.actions if action.forbidden)
    if scenario.kind is TaskKind.NORMAL:
        _require(not forbidden_actions, "normal task contains a forbidden action")
        _require(not scenario.sensitive_values, "normal task contains sensitive labels")
    else:
        _require(bool(forbidden_actions), "attack task has no forbidden action")
        _require(bool(scenario.sensitive_values), "attack task has no sensitive value")
        forbidden_values = tuple(
            value for action in forbidden_actions for value in action.arguments.values()
        )
        for secret in scenario.sensitive_values:
            _require(secret.startswith("SYNTHETIC-SECRET-"), "non-synthetic sensitive label")
            _require(any(secret in value for value in forbidden_values), "unused sensitive label")


def validate_catalog(scenarios: tuple[Scenario, ...]) -> None:
    """Reject ambiguous or score-poisoning benchmark fixtures."""

    _require(0 < len(scenarios) <= 1_000, "invalid catalog size")
    task_ids = [scenario.task_id for scenario in scenarios]
    _require(len(task_ids) == len(set(task_ids)), "duplicate task identifier")
    for scenario in scenarios:
        _validate_scenario(scenario)


def catalog_fingerprint(scenarios: tuple[Scenario, ...]) -> str:
    """Return a stable SHA-256 digest for the complete evaluated contract."""

    validate_catalog(scenarios)
    payload: list[dict[str, object]] = []
    for scenario in scenarios:
        payload.append(
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
                    {"path": record.path, "content": record.content, "trusted": record.trusted}
                    for record in scenario.files
                ],
                "actions": [
                    {
                        "action_id": action.action_id,
                        "tool": action.tool,
                        "arguments": dict(sorted(action.arguments.items())),
                        "derived_from": action.derived_from,
                        "required": action.required,
                        "forbidden": action.forbidden,
                    }
                    for action in scenario.actions
                ],
                "policy": {
                    "allowed_tools": sorted(scenario.policy.allowed_tools),
                    "allowed_recipient_domains": sorted(scenario.policy.allowed_recipient_domains),
                    "writable_path_prefixes": scenario.policy.writable_path_prefixes,
                    "approval_required_tools": sorted(scenario.policy.approval_required_tools),
                    "approved_action_ids": sorted(scenario.policy.approved_action_ids),
                },
                "sensitive_values": scenario.sensitive_values,
            }
        )
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode(), usedforsecurity=False).hexdigest()
