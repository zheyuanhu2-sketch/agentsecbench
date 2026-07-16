from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from agentsecbench.adapters import BudgetLedger, BudgetLimits, FakeModelAdapter
from agentsecbench.artifacts import (
    ResultArtifact,
    deterministic_result_artifact,
    model_result_artifact,
)
from agentsecbench.catalog import build_catalog
from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.experiments import (
    ExperimentAggregationError,
    aggregate_result_artifacts,
    canonical_experiment_bytes,
    experiment_sha256,
    wilson_interval,
    write_experiment_summary,
)
from agentsecbench.model_runner import evaluate_model_scenarios
from agentsecbench.policy import SecurePolicy, UnsafePolicy
from agentsecbench.validation import catalog_fingerprint


def _deterministic(*, secure: bool = True) -> ResultArtifact:
    catalog = build_catalog()
    policy = SecurePolicy() if secure else UnsafePolicy()
    return deterministic_result_artifact(
        evaluate_catalog(catalog, policy),
        package_version="0.6.0",
        catalog_fingerprint=catalog_fingerprint(catalog),
    )


def _model(*, successful: bool) -> ResultArtifact:
    catalog = build_catalog()
    scenario = next(item for item in catalog if item.task_id == "normal-mail-01")
    if successful:
        responses = {
            "normal-mail-01-turn-01": (
                '{"type":"tool_call","tool":"mail.read","arguments":{"message_id":"trusted-01"}}'
            ),
            "normal-mail-01-turn-02": (
                '{"type":"tool_call","tool":"mail.send","arguments":'
                '{"recipient":"reviewer1@example.local","subject":"Approved status 1",'
                '"body":"Milestone 1 is complete."}}'
            ),
            "normal-mail-01-turn-03": ('{"type":"finish","summary":"Task complete."}'),
        }
    else:
        responses = {
            "normal-mail-01-turn-01": "not-json",
            "normal-mail-01-turn-02": (
                '{"type":"finish","summary":"Stopped after protocol recovery."}'
            ),
        }
    summary = evaluate_model_scenarios(
        (scenario,),
        SecurePolicy(),
        FakeModelAdapter(responses),
        BudgetLedger(BudgetLimits()),
        max_turns=4,
    )
    return model_result_artifact(
        summary,
        package_version="0.6.0",
        catalog_fingerprint=catalog_fingerprint(catalog),
        max_turns=4,
        trial_id=("trial-success-0001" if successful else "trial-recovery-0002"),
    )


def _varied_deterministic() -> ResultArtifact:
    artifact = _deterministic()
    tasks = list(artifact.tasks)
    attack_index = next(index for index, task in enumerate(tasks) if task.kind == "attack")
    tasks[attack_index] = replace(tasks[attack_index], attack_success=True, leakage=True)
    return replace(
        artifact,
        metrics=replace(
            artifact.metrics,
            attack_success_rate=0.1,
            leakage_rate=0.1,
        ),
        tasks=tuple(tasks),
    )


def test_wilson_interval_handles_extremes_and_validates_inputs() -> None:
    none = wilson_interval(0, 10)
    all_positive = wilson_interval(10, 10)
    empty = wilson_interval(0, 0)

    assert none.rate == 0.0
    assert none.lower == 0.0
    assert 0.0 < none.upper < 1.0
    assert all_positive.rate == 1.0
    assert 0.0 < all_positive.lower < 1.0
    assert all_positive.upper == 1.0
    assert empty.observations == 0

    with pytest.raises(ExperimentAggregationError, match="counts"):
        wilson_interval(2, 1)
    with pytest.raises(ExperimentAggregationError, match="confidence"):
        wilson_interval(1, 1, confidence=0.5)


def test_deterministic_trials_aggregate_global_and_per_task_intervals() -> None:
    artifact = _deterministic()
    varied = _varied_deterministic()

    summary = aggregate_result_artifacts((artifact, varied), confidence=0.95)

    assert summary.trial_count == 2
    assert summary.utility.positive_count == 60
    assert summary.utility.observations == 60
    assert summary.utility.rate == 1.0
    assert summary.attack_success.positive_count == 1
    assert summary.attack_success.observations == 20
    assert summary.completion is None
    assert summary.protocol_error is None
    assert len(summary.tasks) == 30
    assert summary.tasks[0].attack_success.observations == 0
    assert summary.tasks[-1].attack_success.observations == 2
    assert len(summary.source_digests) == 2


def test_model_trials_aggregate_completion_protocol_errors_tokens_and_instability() -> None:
    successful = _model(successful=True)
    recovered = _model(successful=False)

    summary = aggregate_result_artifacts((successful, recovered))

    assert summary.mode == "model"
    assert summary.utility.rate == 0.5
    assert summary.completion is not None
    assert summary.completion.rate == 1.0
    assert summary.protocol_error is not None
    assert summary.protocol_error.positive_count == 1
    assert summary.protocol_error.observations == 5
    assert summary.input_tokens == (
        successful.metrics.input_tokens + recovered.metrics.input_tokens
    )
    assert summary.tasks[0].completion is not None
    assert summary.tasks[0].utility.rate == 0.5
    assert summary.source_trial_ids == ("trial-success-0001", "trial-recovery-0002")


def test_aggregation_rejects_trial_count_manifest_and_task_mismatches() -> None:
    secure = _deterministic()
    unsafe = _deterministic(secure=False)

    with pytest.raises(ExperimentAggregationError, match="between"):
        aggregate_result_artifacts((secure,))
    with pytest.raises(ExperimentAggregationError, match="duplicate trial"):
        aggregate_result_artifacts((secure, secure))
    with pytest.raises(ExperimentAggregationError, match="manifests"):
        aggregate_result_artifacts((secure, unsafe))

    duplicate_trial_id = _model(successful=False)
    duplicate_trial_id = replace(duplicate_trial_id, trial_id="trial-success-0001")
    with pytest.raises(ExperimentAggregationError, match="trial identifiers"):
        aggregate_result_artifacts((_model(successful=True), duplicate_trial_id))

    mismatched_tasks = ResultArtifact(
        package_version=secure.package_version,
        catalog_fingerprint=secure.catalog_fingerprint,
        mode=secure.mode,
        policy=secure.policy,
        adapter_id=secure.adapter_id,
        model_id=secure.model_id,
        max_turns=secure.max_turns,
        metrics=secure.metrics,
        tasks=tuple(reversed(secure.tasks)),
    )
    with pytest.raises(ExperimentAggregationError, match="task selections"):
        aggregate_result_artifacts((secure, mismatched_tasks))


def test_experiment_summary_is_canonical_content_free_and_atomically_written(
    tmp_path: Path,
) -> None:
    artifact = _deterministic()
    summary = aggregate_result_artifacts((artifact, _varied_deterministic()))
    output = tmp_path / "nested" / "experiment.json"

    digest = write_experiment_summary(output, summary)
    serialized = output.read_text(encoding="utf-8")
    payload = json.loads(serialized)

    assert digest == experiment_sha256(summary)
    assert canonical_experiment_bytes(summary) + b"\n" == output.read_bytes()
    assert payload["schema_version"] == "agentsecbench.experiment.v1"
    assert payload["manifest"]["trial_count"] == 2
    assert "SYNTHETIC-SECRET" not in serialized
    assert "Untrusted content" not in serialized

    with pytest.raises(ExperimentAggregationError, match="JSON file"):
        write_experiment_summary(tmp_path / "experiment.txt", summary)
