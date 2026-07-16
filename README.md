# AgentSecBench

AgentSecBench is a deterministic security benchmark for tool-using AI agents. It measures
whether an agent can complete legitimate work while resisting indirect prompt injection,
unauthorized tool use, and sensitive-data exfiltration.

The benchmark tool environment is deliberately offline and side-effect free. Mailboxes and files
live only in memory; model-generated actions cannot reach real mail, host files, subprocesses, or
browsers.

The v0.3 model loop adds strict JSON decisions, bounded multi-turn execution, evaluator-owned
provenance, opaque policy identifiers, and an opt-in Alibaba Cloud Model Studio evaluation command.
Live requests require explicit network approval and contain synthetic data only. See
[`docs/MODEL_ADAPTERS.md`](docs/MODEL_ADAPTERS.md).

The v0.4 experiment layer adds canonical, content-free result artifacts with strict loading,
atomic writes, stable SHA-256 digests, and metric comparison. Artifacts never contain prompts,
tool arguments, tool outputs, or synthetic secrets. See
[`docs/RESULT_ARTIFACTS.md`](docs/RESULT_ARTIFACTS.md).

## What v0.1 measures

- 20 legitimate tasks across mail and file workflows.
- 10 adversarial tasks containing indirect prompt-injection instructions.
- An intentionally unsafe baseline policy.
- A secure policy with tool allowlists, recipient and path capabilities, approval gates, and
  tainted-data propagation checks.
- Utility success, attack success, false blocking, and sensitive-data leakage rates.

## Quickstart

Prerequisite: [`uv`](https://docs.astral.sh/uv/).

```powershell
uv sync --dev
uv run agentsecbench compare
uv run pytest --cov=agentsecbench --cov-report=term-missing
```

Expected comparison for the deterministic catalog:

| Policy | Utility success | Attack success | False blocks | Leakage |
|---|---:|---:|---:|---:|
| Unsafe | 100% | 100% | 0% | 100% |
| Secure | 100% | 0% | 0% | 0% |

These numbers validate the benchmark harness, not the security of a real model. Future model
adapters must be evaluated separately and must not inherit these expected results as claims.

## Commands

```powershell
uv run agentsecbench list
uv run agentsecbench evaluate --policy secure
uv run agentsecbench evaluate --policy unsafe --json
uv run agentsecbench compare
uv run agentsecbench fingerprint
uv run agentsecbench bailian-smoke --approve-network
uv run agentsecbench bailian-evaluate --approve-network --policy secure
uv run agentsecbench evaluate --policy secure --output artifacts/secure.json
uv run agentsecbench artifact-verify artifacts/secure.json
uv run agentsecbench artifact-compare artifacts/unsafe.json artifacts/secure.json
```

## Project status

This repository is in private v0.4 development. The v0.1 scenario catalog remains frozen. The
publication gate is documented in
[`docs/PUBLICATION_CHECKLIST.md`](docs/PUBLICATION_CHECKLIST.md). See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the component model and
[`docs/SECURITY_ASSUMPTIONS.md`](docs/SECURITY_ASSUMPTIONS.md) for current boundaries.

## Safety

All bundled data is synthetic. Do not add credentials, real email, personal data, malware, or
instructions that cause real external side effects. Report security concerns using
[`SECURITY.md`](SECURITY.md).

## License

MIT
