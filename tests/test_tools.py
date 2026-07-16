import pytest

from agentsecbench.models import FileRecord, Message, PolicyAction
from agentsecbench.tools import InMemoryEnvironment, ToolExecutionError, safe_relative_path


@pytest.mark.parametrize(
    "path",
    ("../secret.txt", "/absolute.txt", "folder/../secret.txt", "folder\\secret.txt", ""),
)
def test_safe_relative_path_rejects_unsafe_values(path: str) -> None:
    with pytest.raises(ToolExecutionError):
        safe_relative_path(path)


def test_reads_propagate_trust_as_taint() -> None:
    environment = InMemoryEnvironment.from_records(
        messages=(Message("m1", "outside@evil.test", "test", "payload", trusted=False),),
        files=(FileRecord("notes/trusted.txt", "safe", trusted=True),),
    )

    message = environment.execute(PolicyAction("a1", "mail.read", {"message_id": "m1"}))
    file_output = environment.execute(
        PolicyAction("a2", "file.read", {"path": "notes/trusted.txt"})
    )

    assert message.tainted is True
    assert file_output.tainted is False


def test_unknown_tool_is_rejected_without_execution() -> None:
    environment = InMemoryEnvironment.from_records((), ())

    with pytest.raises(ToolExecutionError, match="unknown tool"):
        environment.execute(PolicyAction("a1", "shell.exec", {"command": "ignored"}))


@pytest.mark.parametrize(
    ("action", "message"),
    (
        (PolicyAction("a1", "mail.read", {"message_id": "missing"}), "unknown message"),
        (PolicyAction("a2", "file.read", {"path": "missing.txt"}), "unknown file"),
        (
            PolicyAction("a3", "mail.send", {"recipient": "invalid", "subject": "x", "body": "x"}),
            "invalid recipient",
        ),
    ),
)
def test_tool_contract_rejects_invalid_inputs(action: PolicyAction, message: str) -> None:
    environment = InMemoryEnvironment.from_records((), ())

    with pytest.raises(ToolExecutionError, match=message):
        environment.execute(action)
