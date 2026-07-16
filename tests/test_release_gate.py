import importlib.util
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_gate", ROOT / "scripts" / "release_gate.py")
assert SPEC is not None and SPEC.loader is not None
RELEASE_GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_GATE)


def _gate() -> ModuleType:
    return cast(ModuleType, RELEASE_GATE)


def test_source_release_invariants_are_self_consistent() -> None:
    gate = _gate()
    version = gate.check_source(expected_tag=f"v{gate.project_version()}")

    assert version == gate.package_version()


def test_source_release_gate_rejects_mismatched_tag() -> None:
    gate = _gate()
    with pytest.raises(gate.ReleaseGateError, match="tag does not match"):
        gate.check_source(expected_tag="v999.0.0")


def test_release_workflow_recovery_and_build_hygiene_contract() -> None:
    _gate()._check_release_workflow_contract()


def test_release_critical_files_are_tracked() -> None:
    gate = _gate()
    expected_relative = {
        "CITATION.cff",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "docs/SHOWCASE.md",
        "examples/showcase/manifest.json",
        "examples/showcase/secure.result.json",
        "examples/showcase/unsafe.result.json",
        "pyproject.toml",
        "scripts/showcase.py",
        "src/agentsecbench/py.typed",
        "uv.lock",
    }

    assert expected_relative <= set(gate.REQUIRED_PROJECT_FILES)
    assert all((ROOT / relative).is_file() for relative in expected_relative)


@pytest.mark.parametrize(
    "names",
    (
        ("agentsecbench/../escape.py",),
        ("agentsecbench\\escape.py",),
        ("agentsecbench/module.py", "agentsecbench/module.py"),
        ("unexpected/module.py",),
    ),
)
def test_archive_name_gate_rejects_unsafe_or_duplicate_paths(names: tuple[str, ...]) -> None:
    gate = _gate()

    with pytest.raises(gate.ReleaseGateError, match="unsafe archive path"):
        gate._safe_archive_names(names, frozenset({"agentsecbench"}))
