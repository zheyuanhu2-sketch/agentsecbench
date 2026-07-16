from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from agentsecbench.catalog import build_catalog
from agentsecbench.scenario_io import (
    MAX_SCENARIO_FILE_BYTES,
    SCENARIO_SCHEMA_VERSION,
    ScenarioSchemaError,
    load_scenario_catalog,
    parse_scenario_catalog,
    scenario_catalog_dict,
)
from agentsecbench.validation import catalog_fingerprint


def _payload() -> dict[str, object]:
    return deepcopy(scenario_catalog_dict(build_catalog()))


def _first_scenario(payload: dict[str, object]) -> dict[str, object]:
    scenarios = payload["scenarios"]
    assert isinstance(scenarios, list)
    scenario = scenarios[0]
    assert isinstance(scenario, dict)
    return scenario


def test_external_scenario_round_trip_preserves_frozen_catalog_and_fingerprint(
    tmp_path: Path,
) -> None:
    catalog = build_catalog()
    payload = scenario_catalog_dict(catalog)
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = load_scenario_catalog(path)

    assert parsed == catalog
    assert catalog_fingerprint(parsed) == catalog_fingerprint(catalog)
    assert payload["schema_version"] == SCENARIO_SCHEMA_VERSION
    assert payload["data_classification"] == "synthetic"


def test_scenario_parser_rejects_unknown_fields_schema_and_classification() -> None:
    extra = _payload()
    extra["includes"] = ["remote.json"]
    with pytest.raises(ScenarioSchemaError, match="catalog object"):
        parse_scenario_catalog(extra)

    schema = _payload()
    schema["schema_version"] = "agentsecbench.scenario.v999"
    with pytest.raises(ScenarioSchemaError, match="schema version"):
        parse_scenario_catalog(schema)

    classification = _payload()
    classification["data_classification"] = "production"
    with pytest.raises(ScenarioSchemaError, match="synthetic"):
        parse_scenario_catalog(classification)


def test_scenario_parser_rejects_empty_and_malformed_task_data() -> None:
    empty = _payload()
    empty["scenarios"] = []
    with pytest.raises(ScenarioSchemaError, match="must not be empty"):
        parse_scenario_catalog(empty)

    bad_kind = _payload()
    _first_scenario(bad_kind)["kind"] = "unknown"
    with pytest.raises(ScenarioSchemaError, match="task kind"):
        parse_scenario_catalog(bad_kind)

    bad_goal = _payload()
    _first_scenario(bad_goal)["goal"] = ""
    with pytest.raises(ScenarioSchemaError, match="task goal"):
        parse_scenario_catalog(bad_goal)


def test_scenario_parser_rejects_message_file_and_action_shape_errors() -> None:
    bad_message = _payload()
    messages = _first_scenario(bad_message)["messages"]
    assert isinstance(messages, list)
    message = messages[0]
    assert isinstance(message, dict)
    message["body"] = ""
    with pytest.raises(ScenarioSchemaError, match="message body"):
        parse_scenario_catalog(bad_message)

    bad_action = _payload()
    actions = _first_scenario(bad_action)["actions"]
    assert isinstance(actions, list)
    action = actions[0]
    assert isinstance(action, dict)
    action["tool"] = "shell.exec"
    with pytest.raises(ScenarioSchemaError, match="unknown action tool"):
        parse_scenario_catalog(bad_action)

    bad_arguments = _payload()
    argument_actions = _first_scenario(bad_arguments)["actions"]
    assert isinstance(argument_actions, list)
    argument_action = argument_actions[0]
    assert isinstance(argument_action, dict)
    argument_action["arguments"] = {"message_id": "trusted-01", "extra": "x"}
    with pytest.raises(ScenarioSchemaError, match="tool arguments"):
        parse_scenario_catalog(bad_arguments)


def test_scenario_parser_applies_cross_reference_path_and_secret_invariants() -> None:
    unknown_message = _payload()
    actions = _first_scenario(unknown_message)["actions"]
    assert isinstance(actions, list)
    action = actions[0]
    assert isinstance(action, dict)
    arguments = action["arguments"]
    assert isinstance(arguments, dict)
    arguments["message_id"] = "missing-message"
    with pytest.raises(ScenarioSchemaError, match="unknown message"):
        parse_scenario_catalog(unknown_message)

    traversal = _payload()
    scenarios = traversal["scenarios"]
    assert isinstance(scenarios, list)
    file_scenario = scenarios[10]
    assert isinstance(file_scenario, dict)
    files = file_scenario["files"]
    assert isinstance(files, list)
    file_record = files[0]
    assert isinstance(file_record, dict)
    file_record["path"] = "../escape.txt"
    with pytest.raises(ScenarioSchemaError, match="invalid catalog file path"):
        parse_scenario_catalog(traversal)

    secret = _payload()
    secret_scenarios = secret["scenarios"]
    assert isinstance(secret_scenarios, list)
    attack = secret_scenarios[20]
    assert isinstance(attack, dict)
    attack["sensitive_values"] = ["real-secret"]
    with pytest.raises(ScenarioSchemaError, match="non-synthetic"):
        parse_scenario_catalog(secret)


def test_scenario_parser_rejects_duplicate_provenance_approvals_and_policy_tools() -> None:
    duplicate_provenance = _payload()
    actions = _first_scenario(duplicate_provenance)["actions"]
    assert isinstance(actions, list)
    second = actions[1]
    assert isinstance(second, dict)
    second["derived_from"] = ["normal-mail-01-read", "normal-mail-01-read"]
    with pytest.raises(ScenarioSchemaError, match="duplicate provenance"):
        parse_scenario_catalog(duplicate_provenance)

    duplicate_approval = _payload()
    policy = _first_scenario(duplicate_approval)["policy"]
    assert isinstance(policy, dict)
    policy["approved_action_ids"] = ["normal-mail-01-send", "normal-mail-01-send"]
    with pytest.raises(ScenarioSchemaError, match="duplicate approved"):
        parse_scenario_catalog(duplicate_approval)

    unknown_policy_tool = _payload()
    unknown_policy = _first_scenario(unknown_policy_tool)["policy"]
    assert isinstance(unknown_policy, dict)
    unknown_policy["allowed_tools"] = ["mail.read", "shell.exec"]
    with pytest.raises(ScenarioSchemaError, match="unknown tool"):
        parse_scenario_catalog(unknown_policy_tool)


def test_scenario_loader_rejects_duplicate_keys_size_and_bad_paths(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"x","schema_version":"y"}', encoding="utf-8")
    with pytest.raises(ScenarioSchemaError, match="bounded UTF-8 JSON"):
        load_scenario_catalog(duplicate)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (MAX_SCENARIO_FILE_BYTES + 1))
    with pytest.raises(ScenarioSchemaError, match="size"):
        load_scenario_catalog(oversized)

    with pytest.raises(ScenarioSchemaError, match="JSON file"):
        load_scenario_catalog(tmp_path / "catalog.txt")
    with pytest.raises(ScenarioSchemaError, match="existing regular file"):
        load_scenario_catalog(tmp_path / "missing.json")
