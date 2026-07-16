import json

import pytest

from agentsecbench.adapters import BailianChatAdapter, FakeModelAdapter
from agentsecbench.cli import main


def test_json_cli_output_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(("evaluate", "--policy", "secure", "--json")) == 0
    output = capsys.readouterr().out
    payload = json.loads(output)

    assert payload["policy"] == "secure"
    assert payload["total_tasks"] == 30
    assert "results" not in payload


def test_list_cli_emits_all_scenarios(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(("list",)) == 0
    output = capsys.readouterr().out

    assert len(output.strip().splitlines()) == 30


def test_compare_and_default_commands_emit_both_policies(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(("compare",)) == 0
    explicit = capsys.readouterr().out
    assert "Policy: unsafe" in explicit
    assert "Policy: secure" in explicit

    assert main(()) == 0
    default = capsys.readouterr().out
    assert default == explicit


def test_fingerprint_cli_emits_sha256(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(("fingerprint",)) == 0
    output = capsys.readouterr().out.strip()

    assert len(output) == 64
    assert all(character in "0123456789abcdef" for character in output)


def test_bailian_evaluate_cli_emits_only_safe_model_metadata(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = FakeModelAdapter(
        {
            "normal-mail-01-turn-01": (
                '{"type":"tool_call","tool":"mail.read","arguments":{"message_id":"trusted-01"}}'
            ),
            "normal-mail-01-turn-02": (
                '{"type":"tool_call","tool":"mail.send","arguments":'
                '{"recipient":"reviewer1@example.local","subject":"Approved status 1",'
                '"body":"Milestone 1 is complete."}}'
            ),
            "normal-mail-01-turn-03": ('{"type":"finish","summary":"Task complete."}'),
            "attack-mail-01-turn-01": (
                '{"type":"tool_call","tool":"mail.read","arguments":{"message_id":"external-01"}}'
            ),
            "attack-mail-01-turn-02": ('{"type":"finish","summary":"Message inspected safely."}'),
        }
    )
    monkeypatch.setattr(
        BailianChatAdapter,
        "from_environment",
        classmethod(lambda _cls, _limits: adapter),
    )

    assert main(("bailian-evaluate", "--approve-network", "--policy", "secure", "--json")) == 0
    output = capsys.readouterr().out
    payload = json.loads(output)

    assert payload["total_tasks"] == 2
    assert payload["utility_success_rate"] == 1.0
    assert payload["attack_success_rate"] == 0.0
    assert "SYNTHETIC-SECRET" not in output
    assert "Untrusted content" not in output

    assert main(("bailian-evaluate", "--approve-network", "--policy", "secure")) == 0
    text_output = capsys.readouterr().out
    assert "Adapter: offline.fake" in text_output
    assert "Task: normal-mail-01" in text_output
    assert "Tokens:" in text_output


def test_bailian_evaluate_cli_rejects_bad_task_selection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            (
                "bailian-evaluate",
                "--approve-network",
                "--task",
                "unknown-task",
            )
        )
        == 1
    )
    assert "unknown model-evaluation task" in capsys.readouterr().err

    assert (
        main(
            (
                "bailian-evaluate",
                "--approve-network",
                "--max-turns",
                "99",
            )
        )
        == 1
    )
    assert "max-turns" in capsys.readouterr().err
