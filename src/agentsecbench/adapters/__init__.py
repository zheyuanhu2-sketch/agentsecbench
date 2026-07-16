"""Secure model-adapter contracts and offline implementations."""

from agentsecbench.adapters.bailian import BailianChatAdapter, BailianChatConfig
from agentsecbench.adapters.base import (
    AdapterError,
    BudgetExceeded,
    BudgetLedger,
    BudgetLimits,
    ModelAdapter,
    ModelRequest,
    ModelResponse,
)
from agentsecbench.adapters.fake import FakeModelAdapter
from agentsecbench.adapters.redaction import SecretRedactor
from agentsecbench.adapters.transport import SecureJsonTransport, SecureJsonTransportConfig

__all__ = [
    "AdapterError",
    "BudgetExceeded",
    "BudgetLedger",
    "BudgetLimits",
    "BailianChatAdapter",
    "BailianChatConfig",
    "FakeModelAdapter",
    "ModelAdapter",
    "ModelRequest",
    "ModelResponse",
    "SecretRedactor",
    "SecureJsonTransport",
    "SecureJsonTransportConfig",
]
