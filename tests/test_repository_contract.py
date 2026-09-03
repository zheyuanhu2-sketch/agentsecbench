import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "relative_path",
    (
        "docs/SHOWCASE.md",
        "examples/showcase/manifest.json",
        "examples/showcase/secure.result.json",
        "examples/showcase/unsafe.result.json",
        "examples/showcase/index.html",
    ),
)
def test_reproducible_evidence_is_checked_out_with_lf(relative_path: str) -> None:
    completed = subprocess.run(
        ["git", "check-attr", "eol", "--", relative_path],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.rstrip().endswith(": eol: lf")
