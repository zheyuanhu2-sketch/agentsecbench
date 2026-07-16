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


def test_release_critical_files_are_tracked() -> None:
    expected = {
        ROOT / "LICENSE",
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
    }

    assert all(path.is_file() for path in expected)


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
