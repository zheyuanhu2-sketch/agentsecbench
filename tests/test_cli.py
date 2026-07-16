import json

import pytest

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
