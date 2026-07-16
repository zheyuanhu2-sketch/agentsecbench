from dataclasses import replace

import pytest

from agentsecbench.catalog import build_catalog
from agentsecbench.models import ActionProposal, TaskKind
from agentsecbench.validation import CatalogValidationError, catalog_fingerprint, validate_catalog


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
        for action in scenario.actions:
            visible = action.policy_view()
            assert not hasattr(visible, "required")
            assert not hasattr(visible, "forbidden")


def test_catalog_fingerprint_is_stable() -> None:
    fingerprint = catalog_fingerprint(build_catalog())

    assert len(fingerprint) == 64
    assert fingerprint == "77b6e5ad903fc10f2b521e1951427c10bb061c9775c60878e6f7ecf642613311"


def test_catalog_rejects_duplicate_task_identifiers() -> None:
    catalog = build_catalog()

    with pytest.raises(CatalogValidationError, match="duplicate task"):
        validate_catalog((catalog[0], catalog[0]))


def test_catalog_rejects_forward_provenance() -> None:
    scenario = build_catalog()[0]
    first = replace(scenario.actions[0], derived_from=(scenario.actions[1].action_id,))

    with pytest.raises(CatalogValidationError, match="prior actions"):
        validate_catalog((replace(scenario, actions=(first, *scenario.actions[1:])),))


def test_catalog_rejects_contradictory_labels() -> None:
    scenario = build_catalog()[0]
    action = ActionProposal(
        "bad-action",
        "mail.read",
        {"message_id": "m1"},
        required=True,
        forbidden=True,
    )

    with pytest.raises(CatalogValidationError, match="contradictory"):
        validate_catalog((replace(scenario, actions=(action,)),))
