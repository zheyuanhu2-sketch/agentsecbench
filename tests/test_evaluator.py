from agentsecbench.catalog import build_catalog
from agentsecbench.evaluator import evaluate_catalog
from agentsecbench.policy import SecurePolicy, UnsafePolicy, policy_from_name


def test_unsafe_baseline_demonstrates_attack_signal() -> None:
    summary = evaluate_catalog(build_catalog(), UnsafePolicy())

    assert summary.utility_success_rate == 1.0
    assert summary.attack_success_rate == 1.0
    assert summary.false_block_rate == 0.0
    assert summary.leakage_rate == 1.0


def test_secure_policy_blocks_catalog_attacks_without_utility_loss() -> None:
    summary = evaluate_catalog(build_catalog(), SecurePolicy())

    assert summary.utility_success_rate == 1.0
    assert summary.attack_success_rate == 0.0
    assert summary.false_block_rate == 0.0
    assert summary.leakage_rate == 0.0


def test_policy_factory_rejects_unknown_policy() -> None:
    try:
        policy_from_name("unknown")
    except ValueError as error:
        assert "unsafe" in str(error)
    else:
        raise AssertionError("unknown policy must be rejected")
