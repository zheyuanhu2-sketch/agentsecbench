from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from agentsecbench.adapters import BudgetLedger, BudgetLimits, FakeModelAdapter
from agentsecbench.artifacts import (
    MAX_ARTIFACT_BYTES,
    ArtifactValidationError,
    ResultArtifact,
    artifact_sha256,
    canonical_artifact_bytes,
    compare_result_artifacts,
    deterministic_result_artifact,
    load_result_artifact,
    model_result_artifact,
    parse_result_artifact,
    write_result_artifact,
)
from agentsecbench.catalog import build_catalog
from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.model_runner import evaluate_model_scenarios
from agentsecbench.policy import SecurePolicy, UnsafePolicy
from agentsecbench.validation import catalog_fingerprint


def _deterministic(policy: str = "secure") -> ResultArtifact:
    catalog = build_catalog()
    selected_policy = SecurePolicy() if policy == "secure" else UnsafePolicy()
    return deterministic_result_artifact(
        evaluate_catalog(catalog, selected_policy),
        package_version="0.4.0",
        catalog_fingerprint=catalog_fingerprint(catalog),
    )


def _model_artifact(*, trial_id: str | None = None) -> ResultArtifact:
    catalog = build_catalog()
    scenario = next(item for item in catalog if item.task_id == "attack-mail-01")
    adapter = FakeModelAdapter(
        {
            "attack-mail-01-turn-01": (
                '{"type":"tool_call","tool":"mail.read","arguments":{"message_id":"external-01"}}'
            ),
            "attack-mail-01-turn-02": ('{"type":"finish","summary":"Message inspected safely."}'),
        }
    )
    summary = evaluate_model_scenarios(
        (scenario,),
        SecurePolicy(),
        adapter,
        BudgetLedger(BudgetLimits()),
        max_turns=4,
    )
    return model_result_artifact(
        summary,
        package_version="0.4.0",
        catalog_fingerprint=catalog_fingerprint(catalog),
        max_turns=4,
        trial_id=trial_id,
    )


def test_deterministic_artifact_round_trip_is_canonical_and_content_free(tmp_path: Path) -> None:
    artifact = _deterministic()
    output = tmp_path / "nested" / "secure.json"

    digest = write_result_artifact(output, artifact)
    loaded = load_result_artifact(output)
    serialized = output.read_text(encoding="utf-8")

    assert loaded == artifact
    assert digest == artifact_sha256(artifact)
    assert canonical_artifact_bytes(loaded) == canonical_artifact_bytes(artifact)
    assert serialized.endswith("\n")
    assert "SYNTHETIC-SECRET" not in serialized
    assert "Milestone 1 is complete" not in serialized
    assert "Untrusted content" not in serialized
    assert loaded.metrics.input_tokens == 0
    assert all(task.runtime is None for task in loaded.tasks)


def test_model_artifact_round_trip_keeps_only_safe_runtime_metadata(tmp_path: Path) -> None:
    artifact = _model_artifact()
    output = tmp_path / "model.json"

    write_result_artifact(output, artifact)
    loaded = load_result_artifact(output)
    serialized = output.read_text(encoding="utf-8")

    assert loaded.mode == "model"
    assert loaded.adapter_id == "offline.fake"
    assert loaded.max_turns == 4
    assert loaded.tasks[0].runtime is not None
    assert loaded.metrics.input_tokens > 0
    assert "SYNTHETIC-SECRET" not in serialized
    assert "Untrusted content" not in serialized


def test_result_v2_round_trip_carries_safe_explicit_trial_identity(tmp_path: Path) -> None:
    artifact = _model_artifact(trial_id="trial-00000001")
    output = tmp_path / "model-v2.json"

    write_result_artifact(output, artifact)
    loaded = load_result_artifact(output)

    assert loaded.schema_version == "agentsecbench.result.v2"
    assert loaded.trial_id == "trial-00000001"
    assert loaded.to_dict()["manifest"]["trial_id"] == "trial-00000001"

    missing = deepcopy(artifact.to_dict())
    manifest = missing["manifest"]
    assert isinstance(manifest, dict)
    manifest.pop("trial_id")
    with pytest.raises(ArtifactValidationError, match="manifest object"):
        parse_result_artifact(missing)

    invalid = deepcopy(artifact.to_dict())
    invalid_manifest = invalid["manifest"]
    assert isinstance(invalid_manifest, dict)
    invalid_manifest["trial_id"] = "bad id"
    with pytest.raises(ArtifactValidationError, match="trial identifier"):
        parse_result_artifact(invalid)


def test_artifact_comparison_reports_directional_metric_deltas() -> None:
    unsafe = _deterministic("unsafe")
    secure = _deterministic("secure")

    comparison = compare_result_artifacts(unsafe, secure)
    payload = comparison.to_dict()

    assert comparison.same_catalog is True
    assert comparison.same_task_selection is True
    assert comparison.utility_delta == 0.0
    assert comparison.attack_success_delta == -1.0
    assert comparison.leakage_delta == -1.0
    assert payload["candidate_digest"] == artifact_sha256(secure)


def _payload() -> dict[str, object]:
    return deepcopy(_deterministic().to_dict())


def test_artifact_parser_rejects_unknown_fields_and_schema_versions() -> None:
    extra = _payload()
    extra["raw_prompt"] = "must never be accepted"
    with pytest.raises(ArtifactValidationError, match="artifact object"):
        parse_result_artifact(extra)

    schema = _payload()
    schema["schema_version"] = "agentsecbench.result.v999"
    with pytest.raises(ArtifactValidationError, match="schema version"):
        parse_result_artifact(schema)


def test_artifact_parser_rejects_inconsistent_metrics_and_duplicate_tasks() -> None:
    inconsistent = _payload()
    metrics = inconsistent["metrics"]
    assert isinstance(metrics, dict)
    metrics["utility_success_rate"] = 0.0
    with pytest.raises(ArtifactValidationError, match="metrics"):
        parse_result_artifact(inconsistent)

    duplicate = _payload()
    tasks = duplicate["tasks"]
    assert isinstance(tasks, list)
    tasks[1] = deepcopy(tasks[0])
    with pytest.raises(ArtifactValidationError, match="metrics|duplicate task"):
        parse_result_artifact(duplicate)


def test_artifact_parser_rejects_mode_metadata_and_runtime_mismatches() -> None:
    deterministic = _payload()
    manifest = deterministic["manifest"]
    assert isinstance(manifest, dict)
    manifest["adapter_id"] = "unexpected.adapter"
    with pytest.raises(ArtifactValidationError, match="model metadata"):
        parse_result_artifact(deterministic)

    model = deepcopy(_model_artifact().to_dict())
    model_manifest = model["manifest"]
    assert isinstance(model_manifest, dict)
    model_manifest["model_id"] = None
    with pytest.raises(ArtifactValidationError, match="missing adapter"):
        parse_result_artifact(model)

    turn_overrun = deepcopy(_model_artifact().to_dict())
    overrun_tasks = turn_overrun["tasks"]
    assert isinstance(overrun_tasks, list)
    first = overrun_tasks[0]
    assert isinstance(first, dict)
    runtime = first["runtime"]
    assert isinstance(runtime, dict)
    runtime["turns"] = 5
    with pytest.raises(ArtifactValidationError, match="turn limit"):
        parse_result_artifact(turn_overrun)


def test_artifact_parser_rejects_invalid_record_task_and_token_values() -> None:
    invalid_status = _payload()
    tasks = invalid_status["tasks"]
    assert isinstance(tasks, list)
    first = tasks[0]
    assert isinstance(first, dict)
    records = first["records"]
    assert isinstance(records, list)
    record = records[0]
    assert isinstance(record, dict)
    record["status"] = "unknown"
    with pytest.raises(ArtifactValidationError, match="record status"):
        parse_result_artifact(invalid_status)

    invalid_kind = _payload()
    kind_tasks = invalid_kind["tasks"]
    assert isinstance(kind_tasks, list)
    kind_task = kind_tasks[0]
    assert isinstance(kind_task, dict)
    kind_task["kind"] = "oracle"
    with pytest.raises(ArtifactValidationError, match="task kind"):
        parse_result_artifact(invalid_kind)

    bad_tokens = deepcopy(_model_artifact().to_dict())
    token_metrics = bad_tokens["metrics"]
    assert isinstance(token_metrics, dict)
    token_metrics["input_tokens"] = 0
    with pytest.raises(ArtifactValidationError, match="token totals"):
        parse_result_artifact(bad_tokens)


def test_artifact_loader_rejects_duplicates_size_and_bad_paths(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"x","schema_version":"y"}', encoding="utf-8")
    with pytest.raises(ArtifactValidationError, match="bounded UTF-8 JSON"):
        load_result_artifact(duplicate)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (MAX_ARTIFACT_BYTES + 1))
    with pytest.raises(ArtifactValidationError, match="size"):
        load_result_artifact(oversized)

    with pytest.raises(ArtifactValidationError, match="JSON file"):
        write_result_artifact(tmp_path / "result.txt", _deterministic())
    with pytest.raises(ArtifactValidationError, match="existing regular file"):
        load_result_artifact(tmp_path / "missing.json")


def test_parse_result_artifact_rejects_non_objects_empty_tasks_and_invalid_rates() -> None:
    with pytest.raises(ArtifactValidationError, match="artifact object"):
        parse_result_artifact([])

    empty = _payload()
    empty["tasks"] = []
    with pytest.raises(ArtifactValidationError, match="task list"):
        parse_result_artifact(empty)

    bad_rate = _payload()
    metrics = bad_rate["metrics"]
    assert isinstance(metrics, dict)
    metrics["leakage_rate"] = 2.0
    with pytest.raises(ArtifactValidationError, match="leakage rate"):
        parse_result_artifact(bad_rate)
