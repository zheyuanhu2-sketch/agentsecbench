import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from agentsecbench.artifacts import artifact_sha256, load_result_artifact

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("showcase", ROOT / "scripts" / "showcase.py")
assert SPEC is not None and SPEC.loader is not None
SHOWCASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHOWCASE)


def _showcase() -> ModuleType:
    return cast(ModuleType, SHOWCASE)


def test_checked_in_showcase_is_current_and_content_free() -> None:
    showcase = _showcase()

    showcase.check_showcase()
    payload = b"".join(
        path.read_bytes()
        for path in (showcase.UNSAFE_PATH, showcase.SECURE_PATH, showcase.MANIFEST_PATH)
    )

    assert b"SYNTHETIC-SECRET" not in payload
    assert b"Untrusted content" not in payload
    assert b"Milestone 1 is complete" not in payload


def test_showcase_manifest_matches_validated_artifacts() -> None:
    showcase = _showcase()
    manifest = json.loads(showcase.MANIFEST_PATH.read_text(encoding="utf-8"))
    unsafe = load_result_artifact(showcase.UNSAFE_PATH)
    secure = load_result_artifact(showcase.SECURE_PATH)

    assert manifest["schema_version"] == "agentsecbench.showcase.v1"
    assert manifest["package_version"] == "0.9.0"
    assert manifest["catalog_fingerprint"] == unsafe.catalog_fingerprint
    assert manifest["artifacts"]["unsafe"]["artifact_sha256"] == artifact_sha256(unsafe)
    assert manifest["artifacts"]["secure"]["artifact_sha256"] == artifact_sha256(secure)
    assert unsafe.metrics.attack_success_rate == 1.0
    assert secure.metrics.attack_success_rate == 0.0
    assert unsafe.metrics.utility_success_rate == secure.metrics.utility_success_rate == 1.0


def test_showcase_rejects_unexpected_directory_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    showcase = _showcase()
    showcase_directory = tmp_path / "examples" / "showcase"
    monkeypatch.setattr(showcase, "ROOT", tmp_path)
    monkeypatch.setattr(showcase, "SHOWCASE_DIRECTORY", showcase_directory)
    monkeypatch.setattr(showcase, "UNSAFE_PATH", showcase_directory / "unsafe.result.json")
    monkeypatch.setattr(showcase, "SECURE_PATH", showcase_directory / "secure.result.json")
    monkeypatch.setattr(showcase, "MANIFEST_PATH", showcase_directory / "manifest.json")
    monkeypatch.setattr(showcase, "DOCUMENT_PATH", tmp_path / "docs" / "SHOWCASE.md")
    showcase.generate_showcase()
    (showcase_directory / "unexpected").mkdir()

    with pytest.raises(showcase.ShowcaseError, match="missing or unexpected"):
        showcase.check_showcase()
