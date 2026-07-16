"""Comparable repeated-trial aggregation with Wilson score intervals."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from statistics import NormalDist

from agentsecbench.artifacts import (
    ResultArtifact,
    artifact_sha256,
    parse_result_artifact,
)
from agentsecbench.models import TaskKind

EXPERIMENT_SCHEMA_VERSION = "agentsecbench.experiment.v1"
MIN_TRIALS = 2
MAX_TRIALS = 100
MIN_CONFIDENCE = 0.80
MAX_CONFIDENCE = 0.999
MAX_EXPERIMENT_BYTES = 2_097_152


class ExperimentAggregationError(ValueError):
    """Raised when trial artifacts are invalid or not directly comparable."""


@dataclass(frozen=True)
class BernoulliEstimate:
    positive_count: int
    observations: int
    rate: float
    lower: float
    upper: float

    def to_dict(self) -> dict[str, object]:
        return {
            "positive_count": self.positive_count,
            "observations": self.observations,
            "rate": self.rate,
            "lower": self.lower,
            "upper": self.upper,
        }


@dataclass(frozen=True)
class TrialTaskEstimate:
    task_id: str
    kind: str
    utility: BernoulliEstimate
    attack_success: BernoulliEstimate
    false_block: BernoulliEstimate
    leakage: BernoulliEstimate
    completion: BernoulliEstimate | None

    def to_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "kind": self.kind,
            "utility": self.utility.to_dict(),
            "attack_success": self.attack_success.to_dict(),
            "false_block": self.false_block.to_dict(),
            "leakage": self.leakage.to_dict(),
            "completion": None if self.completion is None else self.completion.to_dict(),
        }


@dataclass(frozen=True)
class ExperimentSummary:
    package_version: str
    catalog_fingerprint: str
    mode: str
    policy: str
    adapter_id: str | None
    model_id: str | None
    max_turns: int | None
    confidence: float
    trial_count: int
    source_digests: tuple[str, ...]
    utility: BernoulliEstimate
    attack_success: BernoulliEstimate
    false_block: BernoulliEstimate
    leakage: BernoulliEstimate
    completion: BernoulliEstimate | None
    protocol_error: BernoulliEstimate | None
    input_tokens: int
    output_tokens: int
    tasks: tuple[TrialTaskEstimate, ...]
    schema_version: str = EXPERIMENT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "manifest": {
                "package_version": self.package_version,
                "catalog_fingerprint": self.catalog_fingerprint,
                "mode": self.mode,
                "policy": self.policy,
                "adapter_id": self.adapter_id,
                "model_id": self.model_id,
                "max_turns": self.max_turns,
                "confidence": self.confidence,
                "trial_count": self.trial_count,
                "source_digests": list(self.source_digests),
            },
            "metrics": {
                "utility": self.utility.to_dict(),
                "attack_success": self.attack_success.to_dict(),
                "false_block": self.false_block.to_dict(),
                "leakage": self.leakage.to_dict(),
                "completion": (None if self.completion is None else self.completion.to_dict()),
                "protocol_error": (
                    None if self.protocol_error is None else self.protocol_error.to_dict()
                ),
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
            "tasks": [task.to_dict() for task in self.tasks],
        }


def wilson_interval(
    positive_count: int,
    observations: int,
    *,
    confidence: float = 0.95,
) -> BernoulliEstimate:
    """Return a bounded two-sided Wilson interval for Bernoulli observations."""

    if (
        not isinstance(positive_count, int)
        or isinstance(positive_count, bool)
        or not isinstance(observations, int)
        or isinstance(observations, bool)
        or observations < 0
        or not 0 <= positive_count <= observations
    ):
        raise ExperimentAggregationError("invalid Bernoulli counts")
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not MIN_CONFIDENCE <= float(confidence) <= MAX_CONFIDENCE
    ):
        raise ExperimentAggregationError("confidence is outside the supported range")
    if observations == 0:
        return BernoulliEstimate(0, 0, 0.0, 0.0, 0.0)

    confidence_value = float(confidence)
    z_score = NormalDist().inv_cdf(0.5 + confidence_value / 2.0)
    proportion = positive_count / observations
    z_squared = z_score * z_score
    denominator = 1.0 + z_squared / observations
    center = (proportion + z_squared / (2.0 * observations)) / denominator
    margin = (
        z_score
        * (
            (
                proportion * (1.0 - proportion) / observations
                + z_squared / (4.0 * observations * observations)
            )
            ** 0.5
        )
        / denominator
    )
    return BernoulliEstimate(
        positive_count=positive_count,
        observations=observations,
        rate=round(proportion, 4),
        lower=round(max(0.0, center - margin), 4),
        upper=round(min(1.0, center + margin), 4),
    )


def _empty_estimate() -> BernoulliEstimate:
    return wilson_interval(0, 0)


def _ensure_comparable(artifacts: tuple[ResultArtifact, ...]) -> None:
    digests = tuple(artifact_sha256(artifact) for artifact in artifacts)
    if len(digests) != len(set(digests)):
        raise ExperimentAggregationError(
            "duplicate trial artifact digests cannot establish independent runs"
        )
    baseline = artifacts[0]
    baseline_manifest = (
        baseline.package_version,
        baseline.catalog_fingerprint,
        baseline.mode,
        baseline.policy,
        baseline.adapter_id,
        baseline.model_id,
        baseline.max_turns,
    )
    baseline_tasks = tuple((task.task_id, task.kind) for task in baseline.tasks)
    for artifact in artifacts[1:]:
        candidate_manifest = (
            artifact.package_version,
            artifact.catalog_fingerprint,
            artifact.mode,
            artifact.policy,
            artifact.adapter_id,
            artifact.model_id,
            artifact.max_turns,
        )
        if candidate_manifest != baseline_manifest:
            raise ExperimentAggregationError("trial manifests are not directly comparable")
        if tuple((task.task_id, task.kind) for task in artifact.tasks) != baseline_tasks:
            raise ExperimentAggregationError("trial task selections are not directly comparable")


def _task_estimate(
    artifacts: tuple[ResultArtifact, ...], task_index: int, confidence: float
) -> TrialTaskEstimate:
    tasks = tuple(artifact.tasks[task_index] for artifact in artifacts)
    first = tasks[0]
    count = len(tasks)
    is_normal = first.kind == TaskKind.NORMAL.value
    is_attack = first.kind == TaskKind.ATTACK.value
    completion = None
    if first.runtime is not None:
        completion = wilson_interval(
            sum(task.runtime is not None and task.runtime.finished for task in tasks),
            count,
            confidence=confidence,
        )
    return TrialTaskEstimate(
        task_id=first.task_id,
        kind=first.kind,
        utility=wilson_interval(
            sum(task.utility_success for task in tasks), count, confidence=confidence
        ),
        attack_success=(
            wilson_interval(
                sum(task.attack_success for task in tasks), count, confidence=confidence
            )
            if is_attack
            else _empty_estimate()
        ),
        false_block=(
            wilson_interval(sum(task.false_block for task in tasks), count, confidence=confidence)
            if is_normal
            else _empty_estimate()
        ),
        leakage=(
            wilson_interval(sum(task.leakage for task in tasks), count, confidence=confidence)
            if is_attack
            else _empty_estimate()
        ),
        completion=completion,
    )


def aggregate_result_artifacts(
    artifacts: tuple[ResultArtifact, ...],
    *,
    confidence: float = 0.95,
) -> ExperimentSummary:
    """Aggregate validated, directly comparable result artifacts."""

    if not MIN_TRIALS <= len(artifacts) <= MAX_TRIALS:
        raise ExperimentAggregationError(
            f"an experiment requires between {MIN_TRIALS} and {MAX_TRIALS} trials"
        )
    validated = tuple(parse_result_artifact(artifact.to_dict()) for artifact in artifacts)
    _ensure_comparable(validated)
    if not MIN_CONFIDENCE <= confidence <= MAX_CONFIDENCE:
        raise ExperimentAggregationError("confidence is outside the supported range")

    baseline = validated[0]
    all_tasks = tuple(task for artifact in validated for task in artifact.tasks)
    normal_tasks = tuple(task for task in all_tasks if task.kind == TaskKind.NORMAL.value)
    attack_tasks = tuple(task for task in all_tasks if task.kind == TaskKind.ATTACK.value)
    runtimes = tuple(task.runtime for task in all_tasks if task.runtime is not None)
    completion = None
    protocol_error = None
    if baseline.mode == "model":
        completion = wilson_interval(
            sum(runtime.finished for runtime in runtimes),
            len(runtimes),
            confidence=confidence,
        )
        total_turns = sum(runtime.turns for runtime in runtimes)
        protocol_error = wilson_interval(
            sum(runtime.protocol_errors for runtime in runtimes),
            total_turns,
            confidence=confidence,
        )

    return ExperimentSummary(
        package_version=baseline.package_version,
        catalog_fingerprint=baseline.catalog_fingerprint,
        mode=baseline.mode,
        policy=baseline.policy,
        adapter_id=baseline.adapter_id,
        model_id=baseline.model_id,
        max_turns=baseline.max_turns,
        confidence=round(float(confidence), 4),
        trial_count=len(validated),
        source_digests=tuple(artifact_sha256(artifact) for artifact in validated),
        utility=wilson_interval(
            sum(task.utility_success for task in all_tasks),
            len(all_tasks),
            confidence=confidence,
        ),
        attack_success=wilson_interval(
            sum(task.attack_success for task in attack_tasks),
            len(attack_tasks),
            confidence=confidence,
        ),
        false_block=wilson_interval(
            sum(task.false_block for task in normal_tasks),
            len(normal_tasks),
            confidence=confidence,
        ),
        leakage=wilson_interval(
            sum(task.leakage for task in attack_tasks),
            len(attack_tasks),
            confidence=confidence,
        ),
        completion=completion,
        protocol_error=protocol_error,
        input_tokens=sum(artifact.metrics.input_tokens for artifact in validated),
        output_tokens=sum(artifact.metrics.output_tokens for artifact in validated),
        tasks=tuple(
            _task_estimate(validated, index, confidence) for index in range(len(baseline.tasks))
        ),
    )


def canonical_experiment_bytes(summary: ExperimentSummary) -> bytes:
    return json.dumps(
        summary.to_dict(),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def experiment_sha256(summary: ExperimentSummary) -> str:
    return hashlib.sha256(canonical_experiment_bytes(summary), usedforsecurity=False).hexdigest()


def write_experiment_summary(raw_path: str | os.PathLike[str], summary: ExperimentSummary) -> str:
    """Atomically write one canonical, content-free experiment summary."""

    path = Path(raw_path)
    if not str(path) or len(str(path)) > 4_096 or path.suffix.lower() != ".json":
        raise ExperimentAggregationError("experiment path must identify a JSON file")
    if path.exists() and (path.is_dir() or path.is_symlink()):
        raise ExperimentAggregationError("experiment path must be a regular file")
    payload = canonical_experiment_bytes(summary) + b"\n"
    if len(payload) > MAX_EXPERIMENT_BYTES:
        raise ExperimentAggregationError("experiment summary exceeds the size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ExperimentAggregationError("experiment parent must not be a symbolic link")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        with suppress(OSError):
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise
    return experiment_sha256(summary)
