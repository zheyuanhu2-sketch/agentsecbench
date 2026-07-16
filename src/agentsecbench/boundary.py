"""Opaque policy-session bindings that keep benchmark identifiers private."""

from __future__ import annotations

from dataclasses import replace

from agentsecbench.models import PolicyAction, PolicyContext, Scenario


class PolicySession:
    """Map evaluator identifiers to stable, opaque identifiers for one scenario run."""

    def __init__(self, scenario: Scenario) -> None:
        self._identifiers = {
            action.action_id: f"action-{index:04d}"
            for index, action in enumerate(scenario.actions, start=1)
        }
        self._next_identifier = len(self._identifiers) + 1
        opaque_approvals = frozenset(
            self._identifiers[action_id] for action_id in scenario.policy.approved_action_ids
        )
        self.context = PolicyContext(
            goal=scenario.goal,
            policy=replace(
                scenario.policy,
                approved_action_ids=opaque_approvals,
            ),
        )

    def bind(self, action: PolicyAction) -> PolicyAction:
        """Return an immutable policy view with opaque action and provenance IDs."""

        return PolicyAction(
            action_id=self._identifier_for(action.action_id),
            tool=action.tool,
            arguments=action.arguments,
            derived_from=tuple(
                self._identifier_for(source_id) for source_id in action.derived_from
            ),
        )

    def _identifier_for(self, evaluator_id: str) -> str:
        identifier = self._identifiers.get(evaluator_id)
        if identifier is None:
            identifier = f"action-{self._next_identifier:04d}"
            self._next_identifier += 1
            self._identifiers[evaluator_id] = identifier
        return identifier
