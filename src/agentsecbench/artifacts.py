"""Safe, canonical result artifacts with strict validation and atomic writes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsecbench.model_runner import ModelEvaluationSummary
from agentsecbench.models import ActionRecord, EvaluationSummary, ScenarioResult, TaskKind

RESULT_SCHEMA_V1 = "agentsecbench.result.v1"
RESULT_SCHEMA_V2 = "agentsecbench.result.v2"
RESULT_SCHEMA_VERSION = RESULT_SCHEMA_V1
SUPPORTED_RESULT_SCHEMAS = frozenset({RESULT_SCHEMA_V1, RESULT_SCHEMA_V2})
MAX_ARTIFACT_BYTES = 1_048_576
MAX_ARTIFACT_TASKS = 1_000
MAX_RECORDS_PER_TASK = 128
MAX_REASON_LENGTH = 500
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.-]+)?")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
TRIAL_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{7,127}")


class ArtifactValidationError(ValueError):
    """Raised when an artifact violates the safe result schema."""


@dataclass(frozen=True)
class ArtifactRecord:
    action_id: str
    tool: str
    status: str
    reason: str


@dataclass(frozen=True)
class ArtifactRuntime:
    turns: int
    finished: bool
    protocol_errors: int
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class ArtifactTask:
    task_id: str
    kind: str
    utility_success: bool
    attack_success: bool
    false_block: bool
    leakage: bool
    records: tuple[ArtifactRecord, ...]
    runtime: ArtifactRuntime | None


@dataclass(frozen=True)
class ArtifactMetrics:
    total_tasks: int
    normal_tasks: int
    attack_tasks: int
    utility_success_rate: float
    attack_success_rate: float
    false_block_rate: float
    leakage_rate: float
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class ResultArtifact:
    package_version: str
    catalog_fingerprint: str
    mode: str
    policy: str
    adapter_id: str | None
    model_id: str | None
    max_turns: int | None
    metrics: ArtifactMetrics
    tasks: tuple[ArtifactTask, ...]
    trial_id: str | None = None
    schema_version: str = RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        manifest: dict[str, object] = {
            "package_version": self.package_version,
            "catalog_fingerprint": self.catalog_fingerprint,
            "mode": self.mode,
            "policy": self.policy,
            "adapter_id": self.adapter_id,
            "model_id": self.model_id,
            "max_turns": self.max_turns,
        }
        if self.schema_version == RESULT_SCHEMA_V2:
            manifest["trial_id"] = self.trial_id
        elif self.schema_version != RESULT_SCHEMA_V1:
            raise ArtifactValidationError("unsupported result schema version")
        return {
            "schema_version": self.schema_version,
            "manifest": manifest,
            "metrics": {
                "total_tasks": self.metrics.total_tasks,
                "normal_tasks": self.metrics.normal_tasks,
                "attack_tasks": self.metrics.attack_tasks,
                "utility_success_rate": self.metrics.utility_success_rate,
                "attack_success_rate": self.metrics.attack_success_rate,
                "false_block_rate": self.metrics.false_block_rate,
                "leakage_rate": self.metrics.leakage_rate,
                "input_tokens": self.metrics.input_tokens,
                "output_tokens": self.metrics.output_tokens,
            },
            "tasks": [
                {
                    "task_id": task.task_id,
                    "kind": task.kind,
                    "utility_success": task.utility_success,
                    "attack_success": task.attack_success,
                    "false_block": task.false_block,
                    "leakage": task.leakage,
                    "records": [
                        {
                            "action_id": record.action_id,
                            "tool": record.tool,
                            "status": record.status,
                            "reason": record.reason,
                        }
                        for record in task.records
                    ],
                    "runtime": (
                        None
                        if task.runtime is None
                        else {
                            "turns": task.runtime.turns,
                            "finished": task.runtime.finished,
                            "protocol_errors": task.runtime.protocol_errors,
                            "input_tokens": task.runtime.input_tokens,
                            "output_tokens": task.runtime.output_tokens,
                        }
                    ),
                }
                for task in self.tasks
            ],
        }


@dataclass(frozen=True)
class ArtifactComparison:
    baseline_digest: str
    candidate_digest: str
    same_catalog: bool
    same_task_selection: bool
    utility_delta: float
    attack_success_delta: float
    false_block_delta: float
    leakage_delta: float

    def to_dict(self) -> dict[str, object]:
        return {
            "baseline_digest": self.baseline_digest,
            "candidate_digest": self.candidate_digest,
            "same_catalog": self.same_catalog,
            "same_task_selection": self.same_task_selection,
            "utility_delta": self.utility_delta,
            "attack_success_delta": self.attack_success_delta,
            "false_block_delta": self.false_block_delta,
            "leakage_delta": self.leakage_delta,
        }


def _record(record: ActionRecord) -> ArtifactRecord:
    return ArtifactRecord(
        action_id=record.action_id,
        tool=record.tool,
        status=record.status.value,
        reason=record.reason,
    )


def _task(result: ScenarioResult, runtime: ArtifactRuntime | None) -> ArtifactTask:
    return ArtifactTask(
        task_id=result.task_id,
        kind=result.kind.value,
        utility_success=result.utility_success,
        attack_success=result.attack_success,
        false_block=result.false_block,
        leakage=result.leakage,
        records=tuple(_record(record) for record in result.records),
        runtime=runtime,
    )


def deterministic_result_artifact(
    summary: EvaluationSummary,
    *,
    package_version: str,
    catalog_fingerprint: str,
) -> ResultArtifact:
    """Create a content-free artifact for a deterministic policy evaluation."""

    return ResultArtifact(
        package_version=package_version,
        catalog_fingerprint=catalog_fingerprint,
        mode="deterministic",
        policy=summary.policy,
        adapter_id=None,
        model_id=None,
        max_turns=None,
        metrics=ArtifactMetrics(
            total_tasks=summary.total_tasks,
            normal_tasks=summary.normal_tasks,
            attack_tasks=summary.attack_tasks,
            utility_success_rate=summary.utility_success_rate,
            attack_success_rate=summary.attack_success_rate,
            false_block_rate=summary.false_block_rate,
            leakage_rate=summary.leakage_rate,
            input_tokens=0,
            output_tokens=0,
        ),
        tasks=tuple(_task(result, None) for result in summary.results),
    )


def model_result_artifact(
    summary: ModelEvaluationSummary,
    *,
    package_version: str,
    catalog_fingerprint: str,
    max_turns: int,
    trial_id: str | None = None,
) -> ResultArtifact:
    """Create a redacted model-run artifact with metadata and decisions only."""

    tasks = tuple(
        _task(
            run.result,
            ArtifactRuntime(
                turns=run.turns,
                finished=run.finished,
                protocol_errors=run.protocol_errors,
                input_tokens=run.input_tokens,
                output_tokens=run.output_tokens,
            ),
        )
        for run in summary.runs
    )
    return ResultArtifact(
        package_version=package_version,
        catalog_fingerprint=catalog_fingerprint,
        mode="model",
        policy=summary.policy,
        adapter_id=summary.adapter_id,
        model_id=summary.model_id,
        max_turns=max_turns,
        metrics=ArtifactMetrics(
            total_tasks=summary.total_tasks,
            normal_tasks=summary.normal_tasks,
            attack_tasks=summary.attack_tasks,
            utility_success_rate=summary.utility_success_rate,
            attack_success_rate=summary.attack_success_rate,
            false_block_rate=summary.false_block_rate,
            leakage_rate=summary.leakage_rate,
            input_tokens=summary.input_tokens,
            output_tokens=summary.output_tokens,
        ),
        tasks=tasks,
        trial_id=trial_id,
        schema_version=RESULT_SCHEMA_V2 if trial_id is not None else RESULT_SCHEMA_V1,
    )


def canonical_artifact_bytes(artifact: ResultArtifact) -> bytes:
    """Return stable UTF-8 JSON bytes without a timestamp or machine-specific path."""

    return json.dumps(
        artifact.to_dict(),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def artifact_sha256(artifact: ResultArtifact) -> str:
    return hashlib.sha256(canonical_artifact_bytes(artifact), usedforsecurity=False).hexdigest()


def _safe_artifact_path(raw_path: str | os.PathLike[str]) -> Path:
    path = Path(raw_path)
    if not str(path) or len(str(path)) > 4_096 or path.suffix.lower() != ".json":
        raise ArtifactValidationError("artifact path must identify a JSON file")
    if path.exists() and (path.is_dir() or path.is_symlink()):
        raise ArtifactValidationError("artifact path must be a regular file")
    return path


def write_result_artifact(raw_path: str | os.PathLike[str], artifact: ResultArtifact) -> str:
    """Atomically write one canonical artifact and return its SHA-256 digest."""

    path = _safe_artifact_path(raw_path)
    payload = canonical_artifact_bytes(artifact) + b"\n"
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ArtifactValidationError("artifact exceeds the size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ArtifactValidationError("artifact parent must not be a symbolic link")

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
    return artifact_sha256(artifact)


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactValidationError("artifact contains duplicate keys")
        result[key] = value
    return result


def _exact_object(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ArtifactValidationError(f"invalid {name} object")
    return value


def _string(value: object, name: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or len(value) > MAX_REASON_LENGTH
        or (pattern is not None and not pattern.fullmatch(value))
    ):
        raise ArtifactValidationError(f"invalid {name}")
    return value


def _integer(value: object, name: str, *, maximum: int = 10_000_000) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise ArtifactValidationError(f"invalid {name}")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ArtifactValidationError(f"invalid {name}")
    return value


def _rate_value(value: object, name: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0.0 <= float(value) <= 1.0
    ):
        raise ArtifactValidationError(f"invalid {name}")
    return float(value)


def _optional_identifier(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name, pattern=IDENTIFIER_PATTERN)


def _parse_record(value: object) -> ArtifactRecord:
    data = _exact_object(
        value,
        frozenset({"action_id", "tool", "status", "reason"}),
        "record",
    )
    status = _string(data["status"], "record status")
    if status not in {"executed", "blocked", "error"}:
        raise ArtifactValidationError("invalid record status")
    return ArtifactRecord(
        action_id=_string(data["action_id"], "action identifier", pattern=IDENTIFIER_PATTERN),
        tool=_string(data["tool"], "tool identifier", pattern=IDENTIFIER_PATTERN),
        status=status,
        reason=_string(data["reason"], "record reason"),
    )


def _parse_runtime(value: object, mode: str) -> ArtifactRuntime | None:
    if mode == "deterministic":
        if value is not None:
            raise ArtifactValidationError("deterministic task runtime must be null")
        return None
    data = _exact_object(
        value,
        frozenset({"turns", "finished", "protocol_errors", "input_tokens", "output_tokens"}),
        "runtime",
    )
    turns = _integer(data["turns"], "turn count", maximum=100)
    if turns == 0:
        raise ArtifactValidationError("model task must use at least one turn")
    return ArtifactRuntime(
        turns=turns,
        finished=_boolean(data["finished"], "finished flag"),
        protocol_errors=_integer(data["protocol_errors"], "protocol error count", maximum=100),
        input_tokens=_integer(data["input_tokens"], "input token count"),
        output_tokens=_integer(data["output_tokens"], "output token count"),
    )


def _parse_task(value: object, mode: str) -> ArtifactTask:
    data = _exact_object(
        value,
        frozenset(
            {
                "task_id",
                "kind",
                "utility_success",
                "attack_success",
                "false_block",
                "leakage",
                "records",
                "runtime",
            }
        ),
        "task",
    )
    kind = _string(data["kind"], "task kind")
    if kind not in {TaskKind.NORMAL.value, TaskKind.ATTACK.value}:
        raise ArtifactValidationError("invalid task kind")
    records_value = data["records"]
    if not isinstance(records_value, list) or len(records_value) > MAX_RECORDS_PER_TASK:
        raise ArtifactValidationError("invalid task records")
    return ArtifactTask(
        task_id=_string(data["task_id"], "task identifier", pattern=IDENTIFIER_PATTERN),
        kind=kind,
        utility_success=_boolean(data["utility_success"], "utility flag"),
        attack_success=_boolean(data["attack_success"], "attack flag"),
        false_block=_boolean(data["false_block"], "false-block flag"),
        leakage=_boolean(data["leakage"], "leakage flag"),
        records=tuple(_parse_record(record) for record in records_value),
        runtime=_parse_runtime(data["runtime"], mode),
    )


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _validate_consistency(artifact: ResultArtifact) -> None:
    metrics = artifact.metrics
    tasks = artifact.tasks
    normal = tuple(task for task in tasks if task.kind == TaskKind.NORMAL.value)
    attacks = tuple(task for task in tasks if task.kind == TaskKind.ATTACK.value)
    expected = (
        len(tasks),
        len(normal),
        len(attacks),
        _rate(sum(task.utility_success for task in tasks), len(tasks)),
        _rate(sum(task.attack_success for task in attacks), len(attacks)),
        _rate(sum(task.false_block for task in normal), len(normal)),
        _rate(sum(task.leakage for task in attacks), len(attacks)),
    )
    actual = (
        metrics.total_tasks,
        metrics.normal_tasks,
        metrics.attack_tasks,
        metrics.utility_success_rate,
        metrics.attack_success_rate,
        metrics.false_block_rate,
        metrics.leakage_rate,
    )
    if actual != expected:
        raise ArtifactValidationError("artifact metrics do not match task results")
    if len({task.task_id for task in tasks}) != len(tasks):
        raise ArtifactValidationError("artifact contains duplicate task identifiers")

    runtimes = tuple(task.runtime for task in tasks if task.runtime is not None)
    expected_input = sum(runtime.input_tokens for runtime in runtimes)
    expected_output = sum(runtime.output_tokens for runtime in runtimes)
    if (metrics.input_tokens, metrics.output_tokens) != (expected_input, expected_output):
        raise ArtifactValidationError("artifact token totals do not match task runtimes")
    if (
        artifact.mode == "model"
        and artifact.max_turns is not None
        and any(runtime.turns > artifact.max_turns for runtime in runtimes)
    ):
        raise ArtifactValidationError("task runtime exceeds the manifest turn limit")


def parse_result_artifact(value: object) -> ResultArtifact:
    """Validate a decoded result artifact and return an immutable representation."""

    root = _exact_object(
        value,
        frozenset({"schema_version", "manifest", "metrics", "tasks"}),
        "artifact",
    )
    schema_version = root["schema_version"]
    if schema_version not in SUPPORTED_RESULT_SCHEMAS:
        raise ArtifactValidationError("unsupported result schema version")
    manifest_keys = {
        "package_version",
        "catalog_fingerprint",
        "mode",
        "policy",
        "adapter_id",
        "model_id",
        "max_turns",
    }
    if schema_version == RESULT_SCHEMA_V2:
        manifest_keys.add("trial_id")
    manifest = _exact_object(
        root["manifest"],
        frozenset(manifest_keys),
        "manifest",
    )
    trial_id = None
    if schema_version == RESULT_SCHEMA_V2:
        trial_id = _string(manifest["trial_id"], "trial identifier", pattern=TRIAL_ID_PATTERN)
    mode = _string(manifest["mode"], "run mode")
    if mode not in {"deterministic", "model"}:
        raise ArtifactValidationError("invalid run mode")
    adapter_id = _optional_identifier(manifest["adapter_id"], "adapter identifier")
    model_id = _optional_identifier(manifest["model_id"], "model identifier")
    max_turns_value = manifest["max_turns"]
    if mode == "deterministic":
        if adapter_id is not None or model_id is not None or max_turns_value is not None:
            raise ArtifactValidationError("deterministic manifest contains model metadata")
        max_turns = None
    else:
        if adapter_id is None or model_id is None:
            raise ArtifactValidationError("model manifest is missing adapter metadata")
        max_turns = _integer(max_turns_value, "maximum turns", maximum=100)
        if max_turns == 0:
            raise ArtifactValidationError("model manifest must allow at least one turn")

    metrics_data = _exact_object(
        root["metrics"],
        frozenset(
            {
                "total_tasks",
                "normal_tasks",
                "attack_tasks",
                "utility_success_rate",
                "attack_success_rate",
                "false_block_rate",
                "leakage_rate",
                "input_tokens",
                "output_tokens",
            }
        ),
        "metrics",
    )
    metrics = ArtifactMetrics(
        total_tasks=_integer(metrics_data["total_tasks"], "total task count"),
        normal_tasks=_integer(metrics_data["normal_tasks"], "normal task count"),
        attack_tasks=_integer(metrics_data["attack_tasks"], "attack task count"),
        utility_success_rate=_rate_value(metrics_data["utility_success_rate"], "utility rate"),
        attack_success_rate=_rate_value(metrics_data["attack_success_rate"], "attack success rate"),
        false_block_rate=_rate_value(metrics_data["false_block_rate"], "false-block rate"),
        leakage_rate=_rate_value(metrics_data["leakage_rate"], "leakage rate"),
        input_tokens=_integer(metrics_data["input_tokens"], "input token total"),
        output_tokens=_integer(metrics_data["output_tokens"], "output token total"),
    )
    tasks_value = root["tasks"]
    if (
        not isinstance(tasks_value, list)
        or not tasks_value
        or len(tasks_value) > MAX_ARTIFACT_TASKS
    ):
        raise ArtifactValidationError("invalid artifact task list")
    artifact = ResultArtifact(
        package_version=_string(
            manifest["package_version"], "package version", pattern=VERSION_PATTERN
        ),
        catalog_fingerprint=_string(
            manifest["catalog_fingerprint"],
            "catalog fingerprint",
            pattern=SHA256_PATTERN,
        ),
        mode=mode,
        policy=_string(manifest["policy"], "policy identifier", pattern=IDENTIFIER_PATTERN),
        adapter_id=adapter_id,
        model_id=model_id,
        max_turns=max_turns,
        metrics=metrics,
        tasks=tuple(_parse_task(task, mode) for task in tasks_value),
        trial_id=trial_id,
        schema_version=schema_version,
    )
    _validate_consistency(artifact)
    return artifact


def load_result_artifact(raw_path: str | os.PathLike[str]) -> ResultArtifact:
    """Load a bounded JSON file with duplicate-key rejection and strict validation."""

    path = _safe_artifact_path(raw_path)
    if not path.is_file() or path.is_symlink():
        raise ArtifactValidationError("artifact must be an existing regular file")
    size = path.stat().st_size
    if not 0 < size <= MAX_ARTIFACT_BYTES:
        raise ArtifactValidationError("artifact file size is invalid")
    try:
        decoded: Any = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ArtifactValidationError) as error:
        raise ArtifactValidationError("artifact is not valid bounded UTF-8 JSON") from error
    return parse_result_artifact(decoded)


def compare_result_artifacts(
    baseline: ResultArtifact, candidate: ResultArtifact
) -> ArtifactComparison:
    """Return candidate-minus-baseline metric deltas and comparability signals."""

    baseline_tasks = tuple(task.task_id for task in baseline.tasks)
    candidate_tasks = tuple(task.task_id for task in candidate.tasks)
    return ArtifactComparison(
        baseline_digest=artifact_sha256(baseline),
        candidate_digest=artifact_sha256(candidate),
        same_catalog=baseline.catalog_fingerprint == candidate.catalog_fingerprint,
        same_task_selection=baseline_tasks == candidate_tasks,
        utility_delta=round(
            candidate.metrics.utility_success_rate - baseline.metrics.utility_success_rate, 4
        ),
        attack_success_delta=round(
            candidate.metrics.attack_success_rate - baseline.metrics.attack_success_rate, 4
        ),
        false_block_delta=round(
            candidate.metrics.false_block_rate - baseline.metrics.false_block_rate, 4
        ),
        leakage_delta=round(candidate.metrics.leakage_rate - baseline.metrics.leakage_rate, 4),
    )
