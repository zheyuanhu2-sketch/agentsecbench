# Contributing

AgentSecBench is a public open-source project. Contributions are welcome when they preserve the
benchmark's deterministic, synthetic-data-only, and side-effect-free core.

## Before you start

- Use the issue tracker to check for related work or open a proposal.
- Use the private vulnerability-reporting route in `SECURITY.md` for suspected vulnerabilities.
- Never add credentials, real personal data, confidential repository content, malware, or actions
  that cause real external side effects.
- Read `docs/SCENARIO_CATALOGS.md` before changing benchmark data and
  `docs/MODEL_ADAPTERS.md` before proposing a provider integration.

## Contribution requirements

Contributions must:

1. use synthetic data only;
2. include tests for security-relevant behavior;
3. distinguish benchmark ground truth from controls visible to the policy under test;
4. avoid network, subprocess, and host-filesystem side effects in the core runtime;
5. document new assumptions and residual risks.

## Development workflow

1. Create a focused branch linked to an issue.
2. Add or update tests for every behavior or security-boundary change.
3. Document changed assumptions and residual risks.
4. Run the complete local gate below.
5. Open a pull request using the repository template.

## Complete local gate

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src scripts
uv run pytest --cov=agentsecbench --cov-report=term-missing
uv run agentsecbench compare
uv run agentsecbench catalog-validate examples/coding-agent-scenarios-v1.json
uv audit --locked
uv run python scripts/release_gate.py source
uv run python scripts/showcase.py check
```

## Review and maintenance

Zheyuan Hu is the current primary maintainer. Benchmark-contract, security-boundary, and release
decisions are made through reviewable pull requests. A maintainer may request a smaller scope,
additional adversarial tests, or explicit threat-model changes before accepting security-sensitive
work.

GitHub CI additionally tests Python 3.11 through 3.14, scans the complete Git history with a
checksum-pinned Gitleaks binary, builds the wheel and source distribution twice from one source
epoch, and verifies a clean wheel install.
