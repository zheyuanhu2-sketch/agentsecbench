"""Strict domain models for deterministic agent-security evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class TaskKind(StrEnum):
    NORMAL = "normal"
    ATTACK = "attack"


class ActionStatus(StrEnum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass(frozen=True)
class Message:
    message_id: str
    sender: str
    subject: str
    body: str
    trusted: bool


@dataclass(frozen=True)
class FileRecord:
    path: str
    content: str
    trusted: bool


@dataclass(frozen=True)
class PolicyAction:
    action_id: str
    tool: str
    arguments: Mapping[str, str]
    derived_from: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True)
class ActionProposal:
    action_id: str
    tool: str
    arguments: Mapping[str, str]
    derived_from: tuple[str, ...] = ()
    required: bool = False
    forbidden: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))

    def policy_view(self) -> PolicyAction:
        """Return a copy that cannot expose or mutate evaluator-only labels."""

        return PolicyAction(
            action_id=self.action_id,
            tool=self.tool,
            arguments=self.arguments,
            derived_from=self.derived_from,
        )


@dataclass(frozen=True)
class TaskPolicy:
    allowed_tools: frozenset[str]
    allowed_recipient_domains: frozenset[str] = frozenset()
    writable_path_prefixes: tuple[str, ...] = ()
    approval_required_tools: frozenset[str] = frozenset()
    approved_action_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class PolicyContext:
    """Scenario information visible to a policy under evaluation."""

    goal: str
    policy: TaskPolicy


@dataclass(frozen=True)
class Scenario:
    task_id: str
    kind: TaskKind
    goal: str
    messages: tuple[Message, ...]
    files: tuple[FileRecord, ...]
    actions: tuple[ActionProposal, ...]
    policy: TaskPolicy
    sensitive_values: tuple[str, ...] = ()

    def policy_context(self) -> PolicyContext:
        """Exclude task kind, ground-truth actions, and sensitive-value labels."""

        return PolicyContext(goal=self.goal, policy=self.policy)


@dataclass(frozen=True)
class ToolOutput:
    value: str
    tainted: bool


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class ActionRecord:
    action_id: str
    tool: str
    status: ActionStatus
    reason: str
    output: ToolOutput | None = None


@dataclass(frozen=True)
class ScenarioResult:
    task_id: str
    kind: TaskKind
    records: tuple[ActionRecord, ...]
    utility_success: bool
    attack_success: bool
    false_block: bool
    leakage: bool


@dataclass(frozen=True)
class EvaluationSummary:
    policy: str
    total_tasks: int
    normal_tasks: int
    attack_tasks: int
    utility_success_rate: float
    attack_success_rate: float
    false_block_rate: float
    leakage_rate: float
    results: tuple[ScenarioResult, ...] = field(repr=False)
