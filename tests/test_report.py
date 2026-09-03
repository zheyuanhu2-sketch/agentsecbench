from dataclasses import replace

import pytest

from agentsecbench import __version__
from agentsecbench.artifacts import artifact_sha256, deterministic_result_artifact
from agentsecbench.catalog import build_catalog
from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.policy import SecurePolicy, UnsafePolicy
from agentsecbench.report import ReportError, render_showcase_html
from agentsecbench.validation import catalog_fingerprint


def _inputs():
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
    manifest = {
        "artifacts": {
            "unsafe": {"artifact_sha256": artifact_sha256(unsafe)},
            "secure": {"artifact_sha256": artifact_sha256(secure)},
        }
    }
    return unsafe, secure, manifest


def test_report_is_deterministic_semantic_and_self_contained() -> None:
    unsafe, secure, manifest = _inputs()

    first = render_showcase_html(unsafe, secure, manifest)
    second = render_showcase_html(unsafe, secure, manifest)

    assert first == second
    assert first.endswith(b"\n") and not first.endswith(b"\n\n")
    text = first.decode("utf-8")
    assert text.startswith("<!doctype html>")
    assert text.count("<main") == 1
    assert "<caption>Reference policy comparison</caption>" in text
    assert "<caption>Per-task evaluator outcomes</caption>" in text
    assert "Utility success" in text
    assert "Attack success" in text
    assert unsafe.catalog_fingerprint in text
    assert artifact_sha256(unsafe) in text
    assert artifact_sha256(secure) in text
    assert 'class="skip-link"' in text
    assert 'name="viewport"' in text
    assert "prefers-reduced-motion" in text
    assert "http://" not in text and "https://" not in text


def test_report_escapes_dynamic_values_and_excludes_sensitive_content() -> None:
    unsafe, secure, manifest = _inputs()
    hostile = replace(unsafe, package_version="<script>alert(1)</script>")

    text = render_showcase_html(hostile, secure, manifest).decode("utf-8")

    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "SYNTHETIC-SECRET" not in text
    assert "Untrusted content" not in text
    assert "Milestone 1 is complete" not in text


def test_report_rejects_incomparable_artifacts() -> None:
    unsafe, secure, manifest = _inputs()
    mismatched = replace(secure, catalog_fingerprint="0" * 64)

    with pytest.raises(ReportError, match="catalog"):
        render_showcase_html(unsafe, mismatched, manifest)
