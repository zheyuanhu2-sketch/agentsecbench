"""Command-line interface for local benchmark runs."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from agentsecbench import __version__
from agentsecbench.adapters import (
    AdapterError,
    BailianChatAdapter,
    BudgetLedger,
    BudgetLimits,
    LocalChatAdapter,
    ModelRequest,
)
from agentsecbench.artifacts import (
    ArtifactValidationError,
    artifact_sha256,
    compare_result_artifacts,
    deterministic_result_artifact,
    load_result_artifact,
    model_result_artifact,
    write_result_artifact,
)
from agentsecbench.catalog import build_catalog
from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.experiments import (
    BernoulliEstimate,
    ExperimentAggregationError,
    aggregate_result_artifacts,
    write_experiment_summary,
)
from agentsecbench.model_runner import (
    MAX_DECISION_BYTES,
    MAX_TURNS,
    ModelEvaluationSummary,
    evaluate_model_scenarios,
)
from agentsecbench.models import EvaluationSummary, Scenario
from agentsecbench.policy import policy_from_name
from agentsecbench.scenario_io import ScenarioSchemaError, load_scenario_catalog
from agentsecbench.validation import catalog_fingerprint


def _summary_dict(summary: EvaluationSummary) -> dict[str, object]:
    data = asdict(summary)
    data.pop("results")
    return data


def _print_summary(summary: EvaluationSummary) -> None:
    print(f"Policy: {summary.policy}")
    task_shape = f"{summary.normal_tasks} normal, {summary.attack_tasks} attack"
    print(f"Tasks: {summary.total_tasks} ({task_shape})")
    print(f"Utility success: {summary.utility_success_rate:.0%}")
    print(f"Attack success: {summary.attack_success_rate:.0%}")
    print(f"False blocks: {summary.false_block_rate:.0%}")
    print(f"Leakage: {summary.leakage_rate:.0%}")


def _model_summary_dict(summary: ModelEvaluationSummary) -> dict[str, object]:
    return {
        "policy": summary.policy,
        "adapter_id": summary.adapter_id,
        "model_id": summary.model_id,
        "total_tasks": summary.total_tasks,
        "normal_tasks": summary.normal_tasks,
        "attack_tasks": summary.attack_tasks,
        "utility_success_rate": summary.utility_success_rate,
        "attack_success_rate": summary.attack_success_rate,
        "false_block_rate": summary.false_block_rate,
        "leakage_rate": summary.leakage_rate,
        "input_tokens": summary.input_tokens,
        "output_tokens": summary.output_tokens,
        "tasks": [
            {
                "task_id": run.result.task_id,
                "kind": run.result.kind.value,
                "utility_success": run.result.utility_success,
                "attack_success": run.result.attack_success,
                "false_block": run.result.false_block,
                "leakage": run.result.leakage,
                "turns": run.turns,
                "finished": run.finished,
                "protocol_errors": run.protocol_errors,
            }
            for run in summary.runs
        ],
    }


def _print_model_summary(summary: ModelEvaluationSummary) -> None:
    print(f"Adapter: {summary.adapter_id}")
    print(f"Model: {summary.model_id}")
    print(f"Policy: {summary.policy}")
    for run in summary.runs:
        result = run.result
        print(
            f"Task: {result.task_id} | utility={result.utility_success} "
            f"attack={result.attack_success} leakage={result.leakage} "
            f"turns={run.turns} finished={run.finished} "
            f"protocol_errors={run.protocol_errors}"
        )
    print(f"Utility success: {summary.utility_success_rate:.0%}")
    print(f"Attack success: {summary.attack_success_rate:.0%}")
    print(f"False blocks: {summary.false_block_rate:.0%}")
    print(f"Leakage: {summary.leakage_rate:.0%}")
    print(f"Tokens: {summary.input_tokens} input, {summary.output_tokens} output")


def _format_estimate(name: str, estimate: BernoulliEstimate, confidence: float) -> str:
    confidence_percent = confidence * 100
    return (
        f"{name}: {estimate.rate:.1%} "
        f"({confidence_percent:g}% CI {estimate.lower:.1%}-{estimate.upper:.1%}, "
        f"n={estimate.observations})"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsecbench",
        description="Evaluate security policies for deterministic tool-using agent scenarios.",
    )
    subparsers = parser.add_subparsers(dest="command")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate one policy.")
    evaluate.add_argument("--policy", choices=("unsafe", "secure"), default="secure")
    evaluate.add_argument("--json", action="store_true", help="Emit a compact JSON summary.")
    evaluate.add_argument("--output", help="Atomically write a safe canonical JSON artifact.")

    subparsers.add_parser("compare", help="Compare unsafe and secure policies.")
    subparsers.add_parser("list", help="List scenario identifiers and kinds.")
    subparsers.add_parser("fingerprint", help="Print the stable catalog SHA-256 digest.")
    bailian = subparsers.add_parser(
        "bailian-smoke",
        help="Run one fixed synthetic Bailian connectivity check.",
    )
    bailian.add_argument(
        "--approve-network",
        action="store_true",
        required=True,
        help="Explicitly approve one outbound request to the configured Bailian host.",
    )
    bailian_evaluate = subparsers.add_parser(
        "bailian-evaluate",
        help="Run a bounded synthetic model/tool evaluation through Bailian.",
    )
    bailian_evaluate.add_argument("--policy", choices=("unsafe", "secure"), default="secure")
    bailian_evaluate.add_argument(
        "--task",
        action="append",
        dest="tasks",
        help=(
            "Scenario identifier to evaluate; repeat up to four times. Defaults to one normal "
            "mail task and one indirect-injection mail task."
        ),
    )
    bailian_evaluate.add_argument("--max-turns", type=int, default=4)
    bailian_evaluate.add_argument("--json", action="store_true")
    bailian_evaluate.add_argument(
        "--output", help="Atomically write a redacted canonical JSON artifact."
    )
    bailian_evaluate.add_argument(
        "--approve-network",
        action="store_true",
        required=True,
        help="Explicitly approve the bounded outbound model requests for this run.",
    )
    local_smoke = subparsers.add_parser(
        "local-smoke",
        help="Run one fixed synthetic check against a loopback OpenAI-compatible server.",
    )
    local_smoke.add_argument(
        "--approve-local-network",
        action="store_true",
        required=True,
        help="Explicitly approve one request to a literal loopback address.",
    )
    local_evaluate = subparsers.add_parser(
        "local-evaluate",
        help="Run a bounded synthetic model/tool evaluation on a loopback server.",
    )
    local_evaluate.add_argument("--policy", choices=("unsafe", "secure"), default="secure")
    local_evaluate.add_argument("--task", action="append", dest="tasks")
    local_evaluate.add_argument("--max-turns", type=int, default=4)
    local_evaluate.add_argument("--json", action="store_true")
    local_evaluate.add_argument(
        "--output", help="Atomically write a trial-identified redacted result artifact."
    )
    local_evaluate.add_argument(
        "--approve-local-network",
        action="store_true",
        required=True,
        help="Explicitly approve bounded requests to a literal loopback address.",
    )
    bailian_batch = subparsers.add_parser(
        "bailian-batch",
        help="Run two to five identified Bailian trials and aggregate them.",
    )
    bailian_batch.add_argument("--policy", choices=("unsafe", "secure"), default="secure")
    bailian_batch.add_argument("--task", action="append", dest="tasks")
    bailian_batch.add_argument("--max-turns", type=int, default=4)
    bailian_batch.add_argument("--trials", type=int, default=2)
    bailian_batch.add_argument("--output", required=True)
    bailian_batch.add_argument("--json", action="store_true")
    bailian_batch.add_argument(
        "--approve-network",
        action="store_true",
        required=True,
        help="Explicitly approve all bounded outbound requests in this batch.",
    )
    artifact_verify = subparsers.add_parser(
        "artifact-verify", help="Strictly validate a result artifact."
    )
    artifact_verify.add_argument("path")
    artifact_compare = subparsers.add_parser(
        "artifact-compare", help="Compare two validated result artifacts."
    )
    artifact_compare.add_argument("baseline")
    artifact_compare.add_argument("candidate")
    artifact_compare.add_argument("--json", action="store_true")
    catalog_validate = subparsers.add_parser(
        "catalog-validate", help="Strictly validate an external synthetic scenario catalog."
    )
    catalog_validate.add_argument("path")
    catalog_evaluate = subparsers.add_parser(
        "catalog-evaluate", help="Evaluate an external synthetic scenario catalog."
    )
    catalog_evaluate.add_argument("path")
    catalog_evaluate.add_argument("--policy", choices=("unsafe", "secure"), default="secure")
    catalog_evaluate.add_argument("--json", action="store_true")
    catalog_evaluate.add_argument(
        "--output", help="Atomically write a safe canonical JSON result artifact."
    )
    experiment = subparsers.add_parser(
        "experiment-aggregate",
        help="Aggregate directly comparable result artifacts with confidence intervals.",
    )
    experiment.add_argument("paths", nargs="+")
    experiment.add_argument("--confidence", type=float, default=0.95)
    experiment.add_argument("--json", action="store_true")
    experiment.add_argument("--output", help="Atomically write a canonical experiment summary.")
    return parser


def _select_model_scenarios(
    task_ids: Sequence[str] | None,
) -> tuple[Scenario, ...]:
    catalog = build_catalog()
    requested = tuple(task_ids or ("normal-mail-01", "attack-mail-01"))
    if not requested or len(requested) > 4:
        raise ValueError("select between one and four model-evaluation tasks")
    if len(requested) != len(set(requested)):
        raise ValueError("model-evaluation task identifiers must be unique")
    by_id = {scenario.task_id: scenario for scenario in catalog}
    if any(task_id not in by_id for task_id in requested):
        raise ValueError("unknown model-evaluation task identifier")
    return tuple(by_id[task_id] for task_id in requested)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    command = args.command or "compare"
    catalog = build_catalog()

    if command == "list":
        for scenario in catalog:
            print(f"{scenario.task_id}\t{scenario.kind.value}\t{scenario.goal}")
        return 0

    if command == "fingerprint":
        print(catalog_fingerprint(catalog))
        return 0

    if command == "artifact-verify":
        try:
            artifact = load_result_artifact(args.path)
        except ArtifactValidationError as error:
            print(f"Artifact verification failed: {error}", file=sys.stderr)
            return 1
        print(f"Schema: {artifact.schema_version}")
        print(f"Mode: {artifact.mode}")
        print(f"Policy: {artifact.policy}")
        print(f"Tasks: {artifact.metrics.total_tasks}")
        print(f"SHA-256: {artifact_sha256(artifact)}")
        return 0

    if command == "artifact-compare":
        try:
            comparison = compare_result_artifacts(
                load_result_artifact(args.baseline),
                load_result_artifact(args.candidate),
            )
        except ArtifactValidationError as error:
            print(f"Artifact comparison failed: {error}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(comparison.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"Same catalog: {comparison.same_catalog}")
            print(f"Same task selection: {comparison.same_task_selection}")
            print(f"Utility delta: {comparison.utility_delta:+.0%}")
            print(f"Attack success delta: {comparison.attack_success_delta:+.0%}")
            print(f"False-block delta: {comparison.false_block_delta:+.0%}")
            print(f"Leakage delta: {comparison.leakage_delta:+.0%}")
        return 0

    if command == "catalog-validate":
        try:
            external_catalog = load_scenario_catalog(args.path)
        except ScenarioSchemaError as error:
            print(f"Catalog validation failed: {error}", file=sys.stderr)
            return 1
        normal = sum(scenario.kind.value == "normal" for scenario in external_catalog)
        attack = len(external_catalog) - normal
        print(f"Scenarios: {len(external_catalog)} ({normal} normal, {attack} attack)")
        print(f"Fingerprint: {catalog_fingerprint(external_catalog)}")
        return 0

    if command == "catalog-evaluate":
        try:
            external_catalog = load_scenario_catalog(args.path)
            summary = evaluate_catalog(external_catalog, policy_from_name(args.policy))
            artifact_digest = None
            if args.output:
                artifact_digest = write_result_artifact(
                    args.output,
                    deterministic_result_artifact(
                        summary,
                        package_version=__version__,
                        catalog_fingerprint=catalog_fingerprint(external_catalog),
                    ),
                )
        except (ArtifactValidationError, ScenarioSchemaError) as error:
            print(f"Catalog evaluation failed: {error}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(_summary_dict(summary), indent=2, sort_keys=True))
        else:
            _print_summary(summary)
            if artifact_digest is not None:
                print(f"Artifact SHA-256: {artifact_digest}")
        return 0

    if command == "experiment-aggregate":
        try:
            experiment_summary = aggregate_result_artifacts(
                tuple(load_result_artifact(path) for path in args.paths),
                confidence=args.confidence,
            )
            experiment_digest = None
            if args.output:
                experiment_digest = write_experiment_summary(args.output, experiment_summary)
        except (ArtifactValidationError, ExperimentAggregationError) as error:
            print(f"Experiment aggregation failed: {error}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(experiment_summary.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"Trials: {experiment_summary.trial_count}")
            print(f"Mode: {experiment_summary.mode}")
            print(f"Policy: {experiment_summary.policy}")
            print(
                _format_estimate(
                    "Utility", experiment_summary.utility, experiment_summary.confidence
                )
            )
            print(
                _format_estimate(
                    "Attack success",
                    experiment_summary.attack_success,
                    experiment_summary.confidence,
                )
            )
            print(
                _format_estimate(
                    "False blocks",
                    experiment_summary.false_block,
                    experiment_summary.confidence,
                )
            )
            print(
                _format_estimate(
                    "Leakage", experiment_summary.leakage, experiment_summary.confidence
                )
            )
            if experiment_summary.completion is not None:
                print(
                    _format_estimate(
                        "Completion",
                        experiment_summary.completion,
                        experiment_summary.confidence,
                    )
                )
            if experiment_summary.protocol_error is not None:
                print(
                    _format_estimate(
                        "Protocol errors",
                        experiment_summary.protocol_error,
                        experiment_summary.confidence,
                    )
                )
            print(
                f"Tokens: {experiment_summary.input_tokens} input, "
                f"{experiment_summary.output_tokens} output"
            )
            if experiment_digest is not None:
                print(f"Experiment SHA-256: {experiment_digest}")
        return 0

    if command in {"bailian-smoke", "local-smoke"}:
        limits = BudgetLimits(
            max_requests=1,
            max_input_bytes_per_request=4_096,
            max_total_input_bytes=4_096,
            max_output_tokens_per_request=32,
            max_total_tokens=4_128,
            max_response_bytes=16_384,
            timeout_seconds=30.0,
        )
        expected_marker = (
            "AGENTSECBENCH_BAILIAN_OK" if command == "bailian-smoke" else "AGENTSECBENCH_LOCAL_OK"
        )
        request = ModelRequest(
            request_id=("bailian-smoke-v1" if command == "bailian-smoke" else "local-smoke-v1"),
            system_prompt=(
                "You are a connectivity validator. Do not call tools and do not add explanation."
            ),
            user_prompt=f"Reply with exactly {expected_marker}",
            max_output_tokens=32,
        )
        label = "Bailian" if command == "bailian-smoke" else "Local model"
        try:
            adapter = (
                BailianChatAdapter.from_environment(limits)
                if command == "bailian-smoke"
                else LocalChatAdapter.from_environment(limits)
            )
            response = adapter.complete(request, BudgetLedger(limits))
        except (AdapterError, ValueError) as error:
            print(f"{label} smoke failed: {error}", file=sys.stderr)
            return 1
        matches = response.content.strip() == expected_marker
        print(f"Adapter: {response.adapter_id}")
        print(f"Model: {response.model_id}")
        print(f"Input tokens: {response.input_tokens}")
        print(f"Output tokens: {response.output_tokens}")
        print(f"Expected content: {matches}")
        return 0 if matches else 1

    if command in {"bailian-evaluate", "local-evaluate"}:
        label = "Bailian" if command == "bailian-evaluate" else "Local model"
        try:
            scenarios = _select_model_scenarios(args.tasks)
            if not 1 <= args.max_turns <= MAX_TURNS:
                raise ValueError(f"max-turns must be between 1 and {MAX_TURNS}")
            max_requests = len(scenarios) * args.max_turns
            max_total_input_bytes = max_requests * 32_768
            limits = BudgetLimits(
                max_requests=max_requests,
                max_input_bytes_per_request=32_768,
                max_total_input_bytes=max_total_input_bytes,
                max_output_tokens_per_request=256,
                max_total_tokens=max_total_input_bytes + max_requests * 256,
                max_response_bytes=MAX_DECISION_BYTES,
                timeout_seconds=30.0,
            )
            adapter = (
                BailianChatAdapter.from_environment(limits)
                if command == "bailian-evaluate"
                else LocalChatAdapter.from_environment(limits)
            )
            model_summary = evaluate_model_scenarios(
                scenarios,
                policy_from_name(args.policy),
                adapter,
                BudgetLedger(limits),
                max_turns=args.max_turns,
                max_output_tokens=256,
            )
            artifact_digest = None
            if args.output:
                artifact_digest = write_result_artifact(
                    args.output,
                    model_result_artifact(
                        model_summary,
                        package_version=__version__,
                        catalog_fingerprint=catalog_fingerprint(catalog),
                        max_turns=args.max_turns,
                        trial_id=str(uuid.uuid4()),
                    ),
                )
        except (AdapterError, ArtifactValidationError, ValueError) as error:
            print(f"{label} evaluation failed: {error}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(_model_summary_dict(model_summary), indent=2, sort_keys=True))
        else:
            _print_model_summary(model_summary)
            if artifact_digest is not None:
                print(f"Artifact SHA-256: {artifact_digest}")
        return 0

    if command == "bailian-batch":
        try:
            scenarios = _select_model_scenarios(args.tasks)
            if not 1 <= args.max_turns <= MAX_TURNS:
                raise ValueError(f"max-turns must be between 1 and {MAX_TURNS}")
            if not 2 <= args.trials <= 5:
                raise ValueError("trials must be between 2 and 5")
            output_path = Path(args.output)
            if output_path.suffix.lower() != ".json":
                raise ValueError("batch output must be a JSON file")
            max_requests = len(scenarios) * args.max_turns * args.trials
            max_total_input_bytes = max_requests * 32_768
            limits = BudgetLimits(
                max_requests=max_requests,
                max_input_bytes_per_request=32_768,
                max_total_input_bytes=max_total_input_bytes,
                max_output_tokens_per_request=256,
                max_total_tokens=max_total_input_bytes + max_requests * 256,
                max_response_bytes=MAX_DECISION_BYTES,
                timeout_seconds=30.0,
            )
            adapter = BailianChatAdapter.from_environment(limits)
            ledger = BudgetLedger(limits)
            result_artifacts = []
            for trial_number in range(1, args.trials + 1):
                trial_summary = evaluate_model_scenarios(
                    scenarios,
                    policy_from_name(args.policy),
                    adapter,
                    ledger,
                    max_turns=args.max_turns,
                    max_output_tokens=256,
                )
                result_artifact = model_result_artifact(
                    trial_summary,
                    package_version=__version__,
                    catalog_fingerprint=catalog_fingerprint(catalog),
                    max_turns=args.max_turns,
                    trial_id=str(uuid.uuid4()),
                )
                trial_path = output_path.with_name(
                    f"{output_path.stem}.trial-{trial_number:02d}.result.json"
                )
                write_result_artifact(trial_path, result_artifact)
                result_artifacts.append(result_artifact)
            batch_summary = aggregate_result_artifacts(tuple(result_artifacts))
            batch_digest = write_experiment_summary(output_path, batch_summary)
        except (
            AdapterError,
            ArtifactValidationError,
            ExperimentAggregationError,
            ValueError,
        ) as error:
            print(f"Bailian batch failed: {error}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(batch_summary.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"Trials: {batch_summary.trial_count}")
            print(f"Model: {batch_summary.model_id}")
            print(f"Policy: {batch_summary.policy}")
            print(_format_estimate("Utility", batch_summary.utility, batch_summary.confidence))
            print(
                _format_estimate(
                    "Attack success",
                    batch_summary.attack_success,
                    batch_summary.confidence,
                )
            )
            print(
                f"Tokens: {batch_summary.input_tokens} input, {batch_summary.output_tokens} output"
            )
            print(f"Experiment SHA-256: {batch_digest}")
        return 0

    if command == "evaluate":
        summary = evaluate_catalog(catalog, policy_from_name(args.policy))
        artifact_digest = None
        if args.output:
            try:
                artifact_digest = write_result_artifact(
                    args.output,
                    deterministic_result_artifact(
                        summary,
                        package_version=__version__,
                        catalog_fingerprint=catalog_fingerprint(catalog),
                    ),
                )
            except ArtifactValidationError as error:
                print(f"Artifact write failed: {error}", file=sys.stderr)
                return 1
        if args.json:
            print(json.dumps(_summary_dict(summary), indent=2, sort_keys=True))
        else:
            _print_summary(summary)
            if artifact_digest is not None:
                print(f"Artifact SHA-256: {artifact_digest}")
        return 0

    for name in ("unsafe", "secure"):
        _print_summary(evaluate_catalog(catalog, policy_from_name(name)))
        if name == "unsafe":
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
