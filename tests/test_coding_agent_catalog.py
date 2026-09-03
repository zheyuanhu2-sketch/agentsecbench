from collections import Counter
from pathlib import Path

from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.models import TaskKind
from agentsecbench.policy import SecurePolicy, UnsafePolicy
from agentsecbench.scenario_io import load_scenario_catalog
from agentsecbench.validation import catalog_fingerprint

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "examples" / "coding-agent-scenarios-v1.json"
PAIR_NAMES = {
    "repo-secret-disclosure",
    "issue-write-escape",
    "fixture-scope-escalation",
    "dependency-finding-suppression",
    "pr-instruction-overwrite",
}


def _catalog():
    return load_scenario_catalog(CATALOG_PATH)


def test_coding_agent_catalog_has_five_normal_attack_pairs() -> None:
    catalog = _catalog()

    assert len(catalog) == 10
    assert Counter(item.kind for item in catalog) == {
        TaskKind.NORMAL: 5,
        TaskKind.ATTACK: 5,
    }
    assert {
        item.task_id.removeprefix("normal-").removeprefix("attack-") for item in catalog
    } == PAIR_NAMES


def test_coding_agent_catalog_is_synthetic_and_label_complete() -> None:
    for scenario in _catalog():
        assert all("synthetic" in record.content.lower() for record in scenario.files)
        if scenario.kind is TaskKind.ATTACK:
            assert scenario.sensitive_values
            assert any(action.forbidden for action in scenario.actions)
        else:
            assert not scenario.sensitive_values
            assert any(action.required for action in scenario.actions)


def test_coding_agent_reference_policies_preserve_utility_and_expose_attacks() -> None:
    catalog = _catalog()

    unsafe = evaluate_catalog(catalog, UnsafePolicy())
    secure = evaluate_catalog(catalog, SecurePolicy())

    assert unsafe.utility_success_rate == secure.utility_success_rate == 1.0
    assert unsafe.attack_success_rate == unsafe.leakage_rate == 1.0
    assert secure.attack_success_rate == secure.leakage_rate == 0.0
    assert unsafe.false_block_rate == secure.false_block_rate == 0.0


def test_coding_agent_catalog_fingerprint_is_stable() -> None:
    fingerprint = catalog_fingerprint(_catalog())

    assert len(fingerprint) == 64
    assert fingerprint == "5a3c57196148e667a9378e78bbb8dceea1e2f7cdaeb9f7b6142064eca0479064"
