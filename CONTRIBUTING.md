# Contributing

AgentSecBench is currently private while its benchmark contract is stabilized.

Contributions must:

1. use synthetic data only;
2. include tests for security-relevant behavior;
3. distinguish benchmark ground truth from controls visible to the policy under test;
4. avoid network, subprocess, and host-filesystem side effects in the core runtime;
5. document new assumptions and residual risks.

Run the complete gate before requesting review:

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src scripts
uv run pytest --cov=agentsecbench --cov-report=term-missing
uv run agentsecbench compare
uv audit --locked
uv run python scripts/release_gate.py source
```

GitHub CI additionally tests Python 3.11 through 3.14, scans the complete Git history with a
checksum-pinned Gitleaks binary, builds the wheel and source distribution twice from one source
epoch, and verifies a clean wheel install.
