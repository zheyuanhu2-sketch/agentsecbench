from __future__ import annotations

import json
from pathlib import Path

from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.policy import SecurePolicy, UnsafePolicy
from agentsecbench.scenario_io import load_scenario_catalog

ROOT = Path(__file__).resolve().parents[1]


def test_shipped_example_catalog_is_valid_and_demonstrates_security_delta() -> None:
    catalog = load_scenario_catalog(ROOT / "examples" / "scenario-catalog-v1.json")

    unsafe = evaluate_catalog(catalog, UnsafePolicy())
    secure = evaluate_catalog(catalog, SecurePolicy())

    assert len(catalog) == 2
    assert unsafe.utility_success_rate == 1.0
    assert unsafe.attack_success_rate == 1.0
    assert unsafe.leakage_rate == 1.0
    assert secure.utility_success_rate == 1.0
    assert secure.attack_success_rate == 0.0
    assert secure.leakage_rate == 0.0


def test_shipped_json_schema_is_valid_json_with_expected_identity() -> None:
    schema_path = ROOT / "schemas" / "scenario-catalog-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == ("agentsecbench.scenario.v1")
    assert schema["additionalProperties"] is False
