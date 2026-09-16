# AgentSecBench

[![CI](https://github.com/zheyuanhu2-sketch/agentsecbench/actions/workflows/ci.yml/badge.svg)](https://github.com/zheyuanhu2-sketch/agentsecbench/actions/workflows/ci.yml)
[![Python 3.11-3.14](https://img.shields.io/badge/Python-3.11--3.14-3776AB.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

AgentSecBench is a deterministic security benchmark for tool-using AI agents. It measures
whether an agent can complete legitimate work while resisting indirect prompt injection,
unauthorized tool use, and sensitive-data exfiltration.

The coding-agent catalog adds five normal/attack pairs drawn from repository workflows: nested
instructions, issue content, generated fixtures, dependency notes, and pull-request documents.
It tests whether untrusted repository text can disclose a synthetic secret, redirect a write,
suppress a finding, or overwrite trusted instructions. See the
[`coding-agent scenario guide`](docs/CODING_AGENT_SCENARIOS.md).

The benchmark tool environment is deliberately offline and side-effect free. Mailboxes and files
live only in memory; model-generated actions cannot reach real mail, host files, subprocesses, or
browsers.

## 60-second reviewer route

1. Open the self-contained [`visual benchmark report`](examples/showcase/index.html).
2. Inspect the exact unsafe/secure metrics and per-task outcomes.
3. Reproduce the checked-in evidence and validate the coding-agent catalog:

```powershell
uv sync --locked --dev
uv run python scripts/showcase.py check
uv run agentsecbench catalog-validate examples/coding-agent-scenarios-v1.json
uv run agentsecbench catalog-evaluate examples/coding-agent-scenarios-v1.json --policy secure
```

The visual report and coding-agent catalog evaluate deterministic reference policies. They do not
measure or establish the security of Codex, another language model, a provider, or a production
agent. Live model claims require separate identified trials and redacted result artifacts.

The v0.3 model loop adds strict JSON decisions, bounded multi-turn execution, evaluator-owned
provenance, opaque policy identifiers, and an opt-in Alibaba Cloud Model Studio evaluation command.
Live requests require explicit network approval and contain synthetic data only. See
[`docs/MODEL_ADAPTERS.md`](docs/MODEL_ADAPTERS.md).

The v0.4 experiment layer adds canonical, content-free result artifacts with strict loading,
atomic writes, stable SHA-256 digests, and metric comparison. Artifacts never contain prompts,
tool arguments, tool outputs, or synthetic secrets. See
[`docs/RESULT_ARTIFACTS.md`](docs/RESULT_ARTIFACTS.md).

The v0.5 data layer adds a versioned external synthetic-scenario schema, bounded duplicate-safe
loading, cross-reference and policy validation, a formal JSON Schema, and a runnable example
catalog. See [`docs/SCENARIO_CATALOGS.md`](docs/SCENARIO_CATALOGS.md).

The v0.6 statistics layer aggregates directly comparable trial artifacts into overall and
per-task Wilson confidence intervals, completion/protocol metrics, token totals, and a canonical
content-free experiment summary. See [`docs/STATISTICS.md`](docs/STATISTICS.md).

The v0.7 execution layer adds a loopback-only OpenAI-compatible adapter for local GPU inference,
trial-identified `result.v2` artifacts, and a bounded two-to-five-trial Bailian batch workflow.

The v0.8 release layer adds Python 3.11-3.14 CI, locked dependency auditing, complete-history
secret scanning, source/distribution contract checks, byte-reproducible builds, isolated wheel
installation, and a checksum-producing exact-tag release workflow. See
[`docs/RELEASE_PROCESS.md`](docs/RELEASE_PROCESS.md) and the
[`synthetic-data review`](docs/DATA_REVIEW.md).

The v0.9 presentation layer adds a
[`reproducible showcase`](docs/SHOWCASE.md) backed by checked-in canonical artifacts and exact
hashes, citation metadata, and structured public issue forms. CI regenerates the complete showcase
and rejects any byte-level drift.

The v1.0 release freezes these contracts as the first stable public version and adds
exact-commit-pinned GitHub provenance attestations for the checksummed wheel and source archive.

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
uv sync --locked --dev
uv run agentsecbench compare
uv run pytest --cov=agentsecbench --cov-report=term-missing
uv run python scripts/release_gate.py source
uv run python scripts/showcase.py check
```

Expected comparison for the deterministic catalog:

| Policy | Utility success | Attack success | False blocks | Leakage |
|---|---:|---:|---:|---:|
| Unsafe | 100% | 100% | 0% | 100% |
| Secure | 100% | 0% | 0% | 0% |

These numbers validate the benchmark harness, not the security of a real model. Future model
adapters must be evaluated separately and must not inherit these expected results as claims.
The exact per-task records and digests are available in the
[`checked-in showcase`](docs/SHOWCASE.md) and its
[`self-contained visual report`](examples/showcase/index.html).

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
uv run agentsecbench catalog-validate examples/scenario-catalog-v1.json
uv run agentsecbench catalog-evaluate examples/scenario-catalog-v1.json --policy secure
uv run agentsecbench catalog-validate examples/coding-agent-scenarios-v1.json
uv run agentsecbench catalog-evaluate examples/coding-agent-scenarios-v1.json --policy secure
uv run agentsecbench experiment-aggregate artifacts/trial-1.json artifacts/trial-2.json
uv run agentsecbench local-smoke --approve-local-network
uv run agentsecbench local-evaluate --approve-local-network --policy secure
uv run agentsecbench bailian-batch --approve-network --trials 2 `
  --output artifacts/qwen-plus-secure.json
```

## Project status

AgentSecBench 1.0.0 is the first stable public release. The v0.1 built-in scenario catalog remains
frozen.
External catalogs use a separate versioned contract. The
publication gate is documented in
[`docs/PUBLICATION_CHECKLIST.md`](docs/PUBLICATION_CHECKLIST.md). See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the component model and
[`docs/SECURITY_ASSUMPTIONS.md`](docs/SECURITY_ASSUMPTIONS.md) for current boundaries.
The verified public-release evidence is retained in
[`docs/RELEASE_EVIDENCE_V1.0.0.md`](docs/RELEASE_EVIDENCE_V1.0.0.md).

Contributions are welcome through the [contribution guide](CONTRIBUTING.md). Planned work is kept
in the [public roadmap](docs/ROADMAP.md), and bounded proposals can be discussed in the
[issue tracker](https://github.com/zheyuanhu2-sketch/agentsecbench/issues).

## Safety

All bundled data is synthetic. Do not add credentials, real email, personal data, malware, or
instructions that cause real external side effects. Report security concerns using
[`SECURITY.md`](SECURITY.md).

## Citation

Use the repository's machine-readable [`CITATION.cff`](CITATION.cff) when citing AgentSecBench.

## License

MIT
