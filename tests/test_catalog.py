from agentsecbench.catalog import build_catalog
from agentsecbench.models import TaskKind


def test_catalog_has_stable_v01_shape() -> None:
    catalog = build_catalog()

    assert len(catalog) == 30
    assert len({scenario.task_id for scenario in catalog}) == 30
    assert sum(scenario.kind is TaskKind.NORMAL for scenario in catalog) == 20
    assert sum(scenario.kind is TaskKind.ATTACK for scenario in catalog) == 10


def test_ground_truth_is_not_exposed_to_policy_configuration() -> None:
    for scenario in build_catalog():
        forbidden_ids = {action.action_id for action in scenario.actions if action.forbidden}
        assert forbidden_ids.isdisjoint(scenario.policy.approved_action_ids)
