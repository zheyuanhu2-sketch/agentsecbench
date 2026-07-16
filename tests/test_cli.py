import json
from pathlib import Path

import pytest

from agentsecbench.adapters import BailianChatAdapter, FakeModelAdapter, LocalChatAdapter
from agentsecbench.catalog import build_catalog
from agentsecbench.cli import main
from agentsecbench.scenario_io import scenario_catalog_dict


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
    tmp_path: Path,
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

    model_artifact = tmp_path / "model.json"
    assert (
        main(
            (
                "bailian-evaluate",
                "--approve-network",
                "--policy",
                "secure",
                "--json",
                "--output",
                str(model_artifact),
            )
        )
        == 0
    )
    output = capsys.readouterr().out
    payload = json.loads(output)

    assert payload["total_tasks"] == 2
    assert payload["utility_success_rate"] == 1.0
    assert payload["attack_success_rate"] == 0.0
    assert "SYNTHETIC-SECRET" not in output
    assert "Untrusted content" not in output
    assert model_artifact.is_file()
    model_payload = json.loads(model_artifact.read_text(encoding="utf-8"))
    assert model_payload["schema_version"] == "agentsecbench.result.v2"
    assert model_payload["manifest"]["trial_id"]

    assert main(("bailian-evaluate", "--approve-network", "--policy", "secure")) == 0
    text_output = capsys.readouterr().out
    assert "Adapter: offline.fake" in text_output
    assert "Task: normal-mail-01" in text_output
    assert "Tokens:" in text_output


def test_artifact_cli_write_verify_and_compare(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    unsafe = tmp_path / "unsafe.json"
    secure = tmp_path / "secure.json"

    assert main(("evaluate", "--policy", "unsafe", "--output", str(unsafe))) == 0
    assert "Artifact SHA-256:" in capsys.readouterr().out
    assert main(("evaluate", "--policy", "secure", "--output", str(secure))) == 0
    capsys.readouterr()

    assert main(("artifact-verify", str(secure))) == 0
    verified = capsys.readouterr().out
    assert "Schema: agentsecbench.result.v1" in verified
    assert "Tasks: 30" in verified

    assert main(("artifact-compare", str(unsafe), str(secure), "--json")) == 0
    comparison = json.loads(capsys.readouterr().out)
    assert comparison["same_catalog"] is True
    assert comparison["attack_success_delta"] == -1.0


def test_artifact_cli_rejects_invalid_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}", encoding="utf-8")

    assert main(("artifact-verify", str(invalid))) == 1
    assert "verification failed" in capsys.readouterr().err


def test_external_catalog_cli_validate_evaluate_and_write_artifact(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    catalog_path = tmp_path / "catalog.json"
    artifact_path = tmp_path / "external-result.json"
    catalog_path.write_text(json.dumps(scenario_catalog_dict(build_catalog())), encoding="utf-8")

    assert main(("catalog-validate", str(catalog_path))) == 0
    validated = capsys.readouterr().out
    assert "Scenarios: 30 (20 normal, 10 attack)" in validated
    assert "Fingerprint:" in validated

    assert (
        main(
            (
                "catalog-evaluate",
                str(catalog_path),
                "--policy",
                "secure",
                "--json",
                "--output",
                str(artifact_path),
            )
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["total_tasks"] == 30
    assert summary["attack_success_rate"] == 0.0
    assert artifact_path.is_file()


def test_external_catalog_cli_rejects_invalid_schema(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invalid = tmp_path / "invalid-catalog.json"
    invalid.write_text("{}", encoding="utf-8")

    assert main(("catalog-validate", str(invalid))) == 1
    assert "Catalog validation failed" in capsys.readouterr().err


def test_experiment_aggregate_cli_outputs_intervals_and_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = tmp_path / "trial-1.json"
    second = tmp_path / "trial-2.json"
    experiment = tmp_path / "experiment.json"

    assert main(("evaluate", "--policy", "secure", "--output", str(first))) == 0
    capsys.readouterr()
    assert main(("evaluate", "--policy", "secure", "--output", str(second))) == 0
    capsys.readouterr()
    second_payload = json.loads(second.read_text(encoding="utf-8"))
    second_payload["tasks"][20]["attack_success"] = True
    second_payload["tasks"][20]["leakage"] = True
    second_payload["metrics"]["attack_success_rate"] = 0.1
    second_payload["metrics"]["leakage_rate"] = 0.1
    second.write_text(json.dumps(second_payload), encoding="utf-8")

    assert (
        main(
            (
                "experiment-aggregate",
                str(first),
                str(second),
                "--output",
                str(experiment),
            )
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "Trials: 2" in output
    assert "95% CI" in output
    assert "Experiment SHA-256:" in output
    assert experiment.is_file()

    assert main(("experiment-aggregate", str(first), str(second), "--json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "agentsecbench.experiment.v1"
    assert payload["metrics"]["utility"]["rate"] == 1.0


def test_experiment_aggregate_cli_rejects_non_comparable_inputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secure = tmp_path / "secure.json"
    unsafe = tmp_path / "unsafe.json"
    assert main(("evaluate", "--policy", "secure", "--output", str(secure))) == 0
    capsys.readouterr()
    assert main(("evaluate", "--policy", "unsafe", "--output", str(unsafe))) == 0
    capsys.readouterr()

    assert main(("experiment-aggregate", str(secure), str(unsafe))) == 1
    assert "not directly comparable" in capsys.readouterr().err


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


def test_local_smoke_and_evaluate_cli_use_explicit_loopback_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    smoke_adapter = FakeModelAdapter({"local-smoke-v1": "AGENTSECBENCH_LOCAL_OK"})
    monkeypatch.setattr(
        LocalChatAdapter,
        "from_environment",
        classmethod(lambda _cls, _limits: smoke_adapter),
    )
    assert main(("local-smoke", "--approve-local-network")) == 0
    assert "Expected content: True" in capsys.readouterr().out

    evaluate_adapter = FakeModelAdapter(
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
        }
    )
    monkeypatch.setattr(
        LocalChatAdapter,
        "from_environment",
        classmethod(lambda _cls, _limits: evaluate_adapter),
    )
    output_path = tmp_path / "local-result.json"
    assert (
        main(
            (
                "local-evaluate",
                "--approve-local-network",
                "--task",
                "normal-mail-01",
                "--json",
                "--output",
                str(output_path),
            )
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_tasks"] == 1
    assert payload["utility_success_rate"] == 1.0
    assert output_path.is_file()


def test_bailian_batch_writes_identified_trials_and_experiment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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
    output_path = tmp_path / "batch.json"

    assert (
        main(
            (
                "bailian-batch",
                "--approve-network",
                "--trials",
                "2",
                "--output",
                str(output_path),
                "--json",
            )
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    trial_paths = sorted(tmp_path.glob("batch.trial-*.result.json"))
    trial_payloads = [json.loads(path.read_text(encoding="utf-8")) for path in trial_paths]

    assert summary["manifest"]["trial_count"] == 2
    assert len(summary["manifest"]["source_trial_ids"]) == 2
    assert len(set(summary["manifest"]["source_trial_ids"])) == 2
    assert output_path.is_file()
    assert len(trial_paths) == 2
    assert all(payload["schema_version"] == "agentsecbench.result.v2" for payload in trial_payloads)
    assert len({payload["manifest"]["trial_id"] for payload in trial_payloads}) == 2
    assert "SYNTHETIC-SECRET" not in output_path.read_text(encoding="utf-8")


def test_bailian_batch_rejects_unsafe_bounds_before_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            (
                "bailian-batch",
                "--approve-network",
                "--trials",
                "1",
                "--output",
                str(tmp_path / "batch.json"),
            )
        )
        == 1
    )
    assert "trials must be between" in capsys.readouterr().err
