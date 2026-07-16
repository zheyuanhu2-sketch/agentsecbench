"""Policies under evaluation. They cannot inspect benchmark ground truth labels."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from agentsecbench.models import PolicyAction, PolicyContext, PolicyDecision, ToolOutput
from agentsecbench.tools import ToolExecutionError, safe_relative_path

SIDE_EFFECT_TOOLS = frozenset({"mail.send", "file.write"})


class Policy(Protocol):
    name: str

    def decide(
        self,
        context: PolicyContext,
        action: PolicyAction,
        outputs: Mapping[str, ToolOutput],
    ) -> PolicyDecision: ...


class UnsafePolicy:
    """An intentionally unsafe baseline that permits every known proposal."""

    name = "unsafe"

    def decide(
        self,
        context: PolicyContext,
        action: PolicyAction,
        outputs: Mapping[str, ToolOutput],
    ) -> PolicyDecision:
        del context, action, outputs
        return PolicyDecision(allowed=True, reason="unsafe baseline permits all proposals")


class SecurePolicy:
    """Capability, approval, and taint checks for synthetic tool actions."""

    name = "secure"

    def decide(
        self,
        context: PolicyContext,
        action: PolicyAction,
        outputs: Mapping[str, ToolOutput],
    ) -> PolicyDecision:
        policy = context.policy
        if action.tool not in policy.allowed_tools:
            return PolicyDecision(False, "tool is outside the task capability set")

        if action.tool in SIDE_EFFECT_TOOLS:
            for source_id in action.derived_from:
                source = outputs.get(source_id)
                if source is None:
                    return PolicyDecision(False, "side effect depends on unavailable evidence")
                if source.tainted:
                    return PolicyDecision(False, "untrusted tool output influences a side effect")

        if (
            action.tool in policy.approval_required_tools
            and action.action_id not in policy.approved_action_ids
        ):
            return PolicyDecision(False, "explicit approval is required")

        if action.tool == "mail.send":
            recipient = action.arguments.get("recipient", "")
            domain = recipient.rsplit("@", maxsplit=1)[-1].lower() if "@" in recipient else ""
            if domain not in policy.allowed_recipient_domains:
                return PolicyDecision(False, "recipient is outside the allowed domains")

        if action.tool == "file.write":
            try:
                path = safe_relative_path(action.arguments.get("path", ""))
            except ToolExecutionError:
                return PolicyDecision(False, "write path is invalid")
            if not any(path.startswith(prefix) for prefix in policy.writable_path_prefixes):
                return PolicyDecision(False, "write path is outside the allowed prefixes")

        return PolicyDecision(True, "policy checks passed")


def policy_from_name(name: str) -> Policy:
    if name == "unsafe":
        return UnsafePolicy()
    if name == "secure":
        return SecurePolicy()
    raise ValueError("policy must be 'unsafe' or 'secure'")
