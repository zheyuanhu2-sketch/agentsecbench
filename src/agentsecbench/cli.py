"""Command-line interface for local benchmark runs."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict

from agentsecbench.adapters import (
    AdapterError,
    BailianChatAdapter,
    BudgetLedger,
    BudgetLimits,
    ModelRequest,
)
from agentsecbench.catalog import build_catalog
from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.models import EvaluationSummary
from agentsecbench.policy import policy_from_name
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsecbench",
        description="Evaluate security policies for deterministic tool-using agent scenarios.",
    )
    subparsers = parser.add_subparsers(dest="command")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate one policy.")
    evaluate.add_argument("--policy", choices=("unsafe", "secure"), default="secure")
    evaluate.add_argument("--json", action="store_true", help="Emit a compact JSON summary.")

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
    return parser


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

    if command == "bailian-smoke":
        limits = BudgetLimits(
            max_requests=1,
            max_input_bytes_per_request=4_096,
            max_total_input_bytes=4_096,
            max_output_tokens_per_request=32,
            max_total_tokens=4_128,
            max_response_bytes=16_384,
            timeout_seconds=30.0,
        )
        request = ModelRequest(
            request_id="bailian-smoke-v1",
            system_prompt=(
                "You are a connectivity validator. Do not call tools and do not add explanation."
            ),
            user_prompt="Reply with exactly AGENTSECBENCH_BAILIAN_OK",
            max_output_tokens=32,
        )
        try:
            response = BailianChatAdapter.from_environment(limits).complete(
                request,
                BudgetLedger(limits),
            )
        except (AdapterError, ValueError) as error:
            print(f"Bailian smoke failed: {error}", file=sys.stderr)
            return 1
        matches = response.content.strip() == "AGENTSECBENCH_BAILIAN_OK"
        print(f"Adapter: {response.adapter_id}")
        print(f"Model: {response.model_id}")
        print(f"Input tokens: {response.input_tokens}")
        print(f"Output tokens: {response.output_tokens}")
        print(f"Expected content: {matches}")
        return 0 if matches else 1

    if command == "evaluate":
        summary = evaluate_catalog(catalog, policy_from_name(args.policy))
        if args.json:
            print(json.dumps(_summary_dict(summary), indent=2, sort_keys=True))
        else:
            _print_summary(summary)
        return 0

    for name in ("unsafe", "secure"):
        _print_summary(evaluate_catalog(catalog, policy_from_name(name)))
        if name == "unsafe":
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
