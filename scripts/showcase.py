"""Generate and verify the checked-in deterministic AgentSecBench showcase."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path

from agentsecbench import __version__
from agentsecbench.artifacts import (
    ResultArtifact,
    artifact_sha256,
    canonical_artifact_bytes,
    compare_result_artifacts,
    deterministic_result_artifact,
    load_result_artifact,
)
from agentsecbench.catalog import build_catalog
from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.policy import SecurePolicy, UnsafePolicy
from agentsecbench.report import render_showcase_html
from agentsecbench.validation import catalog_fingerprint

ROOT = Path(__file__).resolve().parents[1]
SHOWCASE_DIRECTORY = ROOT / "examples" / "showcase"
UNSAFE_PATH = SHOWCASE_DIRECTORY / "unsafe.result.json"
SECURE_PATH = SHOWCASE_DIRECTORY / "secure.result.json"
MANIFEST_PATH = SHOWCASE_DIRECTORY / "manifest.json"
HTML_PATH = SHOWCASE_DIRECTORY / "index.html"
DOCUMENT_PATH = ROOT / "docs" / "SHOWCASE.md"
SHOWCASE_SCHEMA_VERSION = "agentsecbench.showcase.v1"
EXPECTED_SHOWCASE_FILES = frozenset(
    {"index.html", "manifest.json", "secure.result.json", "unsafe.result.json"}
)


class ShowcaseError(RuntimeError):
    """Raised when the checked-in showcase differs from generated evidence."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload, usedforsecurity=False).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _result_artifacts() -> tuple[ResultArtifact, ResultArtifact]:
    catalog = build_catalog()
    fingerprint = catalog_fingerprint(catalog)
    unsafe = deterministic_result_artifact(
        evaluate_catalog(catalog, UnsafePolicy()),
        package_version=__version__,
        catalog_fingerprint=fingerprint,
    )
    secure = deterministic_result_artifact(
        evaluate_catalog(catalog, SecurePolicy()),
        package_version=__version__,
        catalog_fingerprint=fingerprint,
    )
    return unsafe, secure


def _artifact_entry(path: Path, artifact: ResultArtifact, payload: bytes) -> dict[str, object]:
    metrics = artifact.metrics
    return {
        "path": path.name,
        "artifact_sha256": artifact_sha256(artifact),
        "file_sha256": _sha256(payload),
        "metrics": {
            "total_tasks": metrics.total_tasks,
            "normal_tasks": metrics.normal_tasks,
            "attack_tasks": metrics.attack_tasks,
            "utility_success_rate": metrics.utility_success_rate,
            "attack_success_rate": metrics.attack_success_rate,
            "false_block_rate": metrics.false_block_rate,
            "leakage_rate": metrics.leakage_rate,
        },
    }


def _percentage(value: float) -> str:
    return f"{value:.0%}"


def _showcase_markdown(
    unsafe: ResultArtifact,
    secure: ResultArtifact,
    manifest: Mapping[str, object],
) -> bytes:
    comparison = compare_result_artifacts(unsafe, secure)
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict):
        raise ShowcaseError("generated showcase manifest has invalid artifacts")
    unsafe_entry = artifacts["unsafe"]
    secure_entry = artifacts["secure"]
    if not isinstance(unsafe_entry, dict) or not isinstance(secure_entry, dict):
        raise ShowcaseError("generated showcase manifest has invalid artifact entries")
    unsafe_row = " | ".join(
        (
            "Unsafe",
            _percentage(unsafe.metrics.utility_success_rate),
            _percentage(unsafe.metrics.attack_success_rate),
            _percentage(unsafe.metrics.false_block_rate),
            _percentage(unsafe.metrics.leakage_rate),
        )
    )
    secure_row = " | ".join(
        (
            "Secure",
            _percentage(secure.metrics.utility_success_rate),
            _percentage(secure.metrics.attack_success_rate),
            _percentage(secure.metrics.false_block_rate),
            _percentage(secure.metrics.leakage_rate),
        )
    )
    unsafe_artifact_sha = unsafe_entry["artifact_sha256"]
    unsafe_file_sha = unsafe_entry["file_sha256"]
    secure_artifact_sha = secure_entry["artifact_sha256"]
    secure_file_sha = secure_entry["file_sha256"]
    manifest_file_sha = _sha256(_json_bytes(manifest))
    unsafe_digest_row = (
        "[`unsafe.result.json`](../examples/showcase/unsafe.result.json) "
        f"| `{unsafe_artifact_sha}` | `{unsafe_file_sha}`"
    )
    secure_digest_row = (
        "[`secure.result.json`](../examples/showcase/secure.result.json) "
        f"| `{secure_artifact_sha}` | `{secure_file_sha}`"
    )
    text = f"""# Reproducible showcase

This page is generated from the frozen built-in catalog and the two reference policies by
`scripts/showcase.py`. CI recreates every linked JSON file and this page byte-for-byte. The
snapshot contains evaluator metadata only: no prompts, tool arguments, tool outputs, message
bodies, file contents, endpoints, credentials, or synthetic sensitive values.

Catalog SHA-256: `{unsafe.catalog_fingerprint}`. Package version: `{__version__}`.

## Deterministic reference result

| Policy | Utility success | Attack success | False blocks | Leakage |
|---|---:|---:|---:|---:|
| {unsafe_row} |
| {secure_row} |

The secure-minus-unsafe delta is {comparison.utility_delta:+.0%} utility,
{comparison.attack_success_delta:+.0%} attack success,
{comparison.false_block_delta:+.0%} false blocks, and
{comparison.leakage_delta:+.0%} leakage. Both artifacts use the same catalog and ordered task
selection.

## Checked-in evidence

| File | Canonical artifact SHA-256 | File SHA-256 |
|---|---|---|
| {unsafe_digest_row} |
| {secure_digest_row} |
| [`manifest.json`](../examples/showcase/manifest.json) | n/a | `{manifest_file_sha}` |

The artifact digest follows the public artifact contract and excludes the trailing newline. The
file digest covers the exact checked-in bytes.

## Reproduce

```powershell
uv sync --locked --dev
uv run python scripts/showcase.py check
uv run agentsecbench artifact-verify examples/showcase/unsafe.result.json
uv run agentsecbench artifact-verify examples/showcase/secure.result.json
uv run agentsecbench artifact-compare examples/showcase/unsafe.result.json `
  examples/showcase/secure.result.json --json
```

To intentionally regenerate the snapshot after an approved version or benchmark-contract change:

```powershell
uv run python scripts/showcase.py generate
```

Review every resulting diff. A changed catalog fingerprint, task selection, metric, action record,
or digest is a benchmark-contract change, not formatting noise.

## Interpretation boundary

These values demonstrate the harness and the intentionally contrasting reference policies. They
do not establish that a language model, provider, or production agent is secure. Model claims
require identified repeated trials, retained redacted artifacts, confidence intervals, and the
limitations described in [`EXPERIMENTS.md`](EXPERIMENTS.md).
"""
    return text.encode("utf-8")


def expected_outputs() -> dict[Path, bytes]:
    """Return every showcase file as deterministic bytes."""

    unsafe, secure = _result_artifacts()
    unsafe_payload = canonical_artifact_bytes(unsafe) + b"\n"
    secure_payload = canonical_artifact_bytes(secure) + b"\n"
    comparison = compare_result_artifacts(unsafe, secure)
    manifest: dict[str, object] = {
        "schema_version": SHOWCASE_SCHEMA_VERSION,
        "package_version": __version__,
        "catalog_fingerprint": unsafe.catalog_fingerprint,
        "artifacts": {
            "unsafe": _artifact_entry(UNSAFE_PATH, unsafe, unsafe_payload),
            "secure": _artifact_entry(SECURE_PATH, secure, secure_payload),
        },
        "comparison": comparison.to_dict(),
    }
    manifest_payload = _json_bytes(manifest)
    return {
        UNSAFE_PATH: unsafe_payload,
        SECURE_PATH: secure_payload,
        MANIFEST_PATH: manifest_payload,
        HTML_PATH: render_showcase_html(unsafe, secure, manifest),
        DOCUMENT_PATH: _showcase_markdown(unsafe, secure, manifest),
    }


def _atomic_write(path: Path, payload: bytes) -> None:
    resolved_root = ROOT.resolve()
    resolved_parent = path.parent.resolve()
    try:
        resolved_parent.relative_to(resolved_root)
    except ValueError as error:
        raise ShowcaseError("showcase output leaves the repository") from error
    if path.parent.is_symlink() or path.is_symlink():
        raise ShowcaseError("showcase output path must not use a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def generate_showcase() -> None:
    """Write the exact generated showcase files."""

    for path, payload in expected_outputs().items():
        _atomic_write(path, payload)


def check_showcase() -> None:
    """Require checked-in showcase files to match generated evidence exactly."""

    expected = expected_outputs()
    if SHOWCASE_DIRECTORY.is_symlink() or DOCUMENT_PATH.is_symlink() or HTML_PATH.is_symlink():
        raise ShowcaseError("showcase paths must not use symbolic links")
    try:
        actual_names = frozenset(path.name for path in SHOWCASE_DIRECTORY.iterdir())
    except OSError as error:
        raise ShowcaseError("cannot inspect the showcase directory") from error
    if actual_names != EXPECTED_SHOWCASE_FILES:
        raise ShowcaseError("showcase directory contains missing or unexpected files")
    for path, payload in expected.items():
        try:
            if path.is_symlink() or not path.is_file():
                raise ShowcaseError(
                    f"showcase path is not a regular file: {path.relative_to(ROOT)}"
                )
            actual = path.read_bytes()
        except OSError as error:
            raise ShowcaseError(f"cannot read showcase file: {path.relative_to(ROOT)}") from error
        if actual != payload:
            raise ShowcaseError(f"showcase file is stale: {path.relative_to(ROOT)}")

    unsafe = load_result_artifact(UNSAFE_PATH)
    secure = load_result_artifact(SECURE_PATH)
    comparison = compare_result_artifacts(unsafe, secure)
    if (
        not comparison.same_catalog
        or not comparison.same_task_selection
        or comparison.utility_delta != 0.0
        or comparison.attack_success_delta != -1.0
        or comparison.false_block_delta != 0.0
        or comparison.leakage_delta != -1.0
    ):
        raise ShowcaseError("showcase security delta is inconsistent")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "generate"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    command = _parser().parse_args(argv).command
    try:
        if command == "generate":
            generate_showcase()
            print("Showcase files generated.")
        else:
            check_showcase()
            print("Showcase files are current and reproducible.")
    except ShowcaseError as error:
        print(f"Showcase check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
